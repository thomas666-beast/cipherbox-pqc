package Cipherbox::Controller::Auth;
use Mojo::Base 'Mojolicious::Controller', -signatures;
use Crypt::JWT qw(encode_jwt decode_jwt);
use Crypt::PRNG qw(random_bytes);
use MIME::Base64 ();
use Mojo::IOLoop;

my $COOKIE_NAME    = 'cipherbox_token';
my $COOKIE_MAX_AGE = 60 * 60 * 24 * 7;
my $pqc_inflight = 0;

sub _valid_pqc_keys ($self, $dsa, $kem) {
    return $self->pqc->valid_base64($dsa, 1952, 2592)
        && $self->pqc->valid_base64($kem, 1184, 1216, 1568, 1600);
}

sub _set_token_cookie ($self, $token) {
    $self->cookie(
        $COOKIE_NAME => $token,
        {
            httponly => 1,
            secure   => $self->req->is_secure ? 1 : 0,
            samesite => 'Strict',
            path     => '/',
            max_age  => $COOKIE_MAX_AGE,
        },
    );
}

sub _clear_token_cookie ($self) {
    $self->cookie(
        $COOKIE_NAME => '',
        {
            httponly => 1,
            secure   => $self->req->is_secure ? 1 : 0,
            samesite => 'Strict',
            path     => '/',
            max_age  => 0,
        },
    );
}

sub register ($self) {
    my $enabled = $self->settings->bool('registration_enabled', 1);
    return $self->render(json => { error => 'registration is disabled' }, status => 403)
        unless $enabled;

    my $ip = $self->client_ip;
    $self->auth_attempts->_cleanup;

    my $reg_limit = $self->auth_limits->{registrations_per_hour} // 3;
    my $recent = $self->auth_attempts->recent_registrations($ip);
    if ($recent >= $reg_limit) {
        return $self->render(json => { error => 'too many registrations' }, status => 429);
    }

    my $body     = $self->req->json;
    return $self->render(json => { error => 'expected a JSON object' }, status => 400)
        unless ref($body) eq 'HASH';
    my $username = $body->{username} // '';
    my $dsa_key  = $body->{dilithium_public_key};
    my $kem_key  = $body->{kyber_public_key};

    return $self->render(json => { error => 'missing fields' }, status => 400)
        unless !ref($username) && length($username) && length($username) <= 128;
    return $self->render(json => { error => 'invalid public key encoding' }, status => 400)
        unless $self->_valid_pqc_keys($dsa_key, $kem_key);

    my $exists = eval { $self->users->find_by_username($username) };
    return $self->render(json => { error => 'username taken' }, status => 409)
        if $exists;

    my $user_count = $self->pg->db->query('SELECT count(*) FROM users')->array->[0];
    my $role = $user_count == 0 ? 'admin' : 'user';    

    my $user = eval { $self->users->create_pqc($username, $dsa_key, $kem_key, $role) };
    if ($@) {
        return $self->render(json => { error => "$@" }, status => 500);
    }

    $self->auth_attempts->record_registration($ip);

    my $now = time;
    my $token = eval {
        encode_jwt(
            payload => {
                uid => $user->{id}, username => $user->{username}, role => $user->{role},
                iat => $now, exp => $now + $COOKIE_MAX_AGE,
            },
            alg     => 'HS256',
            key     => $self->jwt_secret,
        );
    };
    if ($@) {
        return $self->render(json => { error => "jwt: $@" }, status => 500);
    }

    $self->_set_token_cookie($token);

    $self->render(json => { 
        ok => 1, 
        id => $user->{id}, 
        username => $user->{username}, 
        role => $user->{role},
        token => $token 
    });
}

sub login ($self) {
    my $ip = $self->client_ip;

    $self->auth_attempts->_cleanup;

    my $body     = $self->req->json;
    my $username = $body->{username} // '';
    my $password = $body->{password} // '';

    my $fail_limit = $self->auth_limits->{login_failures_per_15min} // 5;

    if (length $username) {
        my $failures = $self->auth_attempts->recent_failures($ip, $username);
        if ($failures >= $fail_limit) {
            $self->res->headers->header('Retry-After' => '900');
            return $self->render(
                json   => { error => 'too many attempts, try again later' },
                status => 429,
            );
        }
    }

    my $user = $self->users->find_by_username($username);
    if (!$user or !$self->users->verify_password($user, $password)) {
        $self->auth_attempts->record_failure($ip, $username) if length $username;
        return $self->render(json => { error => 'invalid credentials' }, status => 401);
    }

    $self->auth_attempts->clear_failures($ip, $username);

    my $token = eval {
        encode_jwt(
            payload => {
                uid      => $user->{id},
                username => $user->{username},
                role     => $user->{role},
            },
            alg => 'HS256',
            key => $self->jwt_secret,
        );
    };
    if ($@) {
        return $self->render(json => { error => "jwt: $@" }, status => 500);
    }

    $self->_set_token_cookie($token);

    my $response = {
        ok       => 1,
        username => $user->{username},
        role     => $user->{role},
    };
    if (($ENV{CIPHERBOX_ENV} // '') eq 'test') {
        $response->{token} = $token;
    }

    $self->render(json => $response);
}

sub logout ($self) {
    $self->_clear_token_cookie;
    $self->render(json => { ok => 1 });
}

sub me ($self) {
    my $user = $self->current_user;
    return $self->render(json => { error => 'unauthorized' }, status => 401)
        unless $user;
    $self->render(json => {
        id       => $user->{id},
        username => $user->{username},
        role     => $user->{role},
    });
}

sub ws_token ($self) {
    my $user = $self->current_user;
    return $self->render(json => { error => 'unauthorized' }, status => 401)
        unless $user;

    my $now = time;
    my $token = eval {
        encode_jwt(
            payload => {
                uid      => $user->{id},
                username => $user->{username},
                role     => $user->{role},
                iat      => $now,
                exp      => $now + 60,
                ws       => 1,
            },
            alg => 'HS256',
            key => $self->jwt_secret,
        );
    };
    if ($@) {
        return $self->render(json => { error => "jwt: $@" }, status => 500);
    }

    $self->render(json => { token => $token });
}

sub save_pqc_keys ($self) {
    my $user = $self->current_user;
    return $self->render(json => { error => 'unauthorized' }, status => 401)
        unless $user;

    my $body = $self->req->json;
    return $self->render(json => { error => 'expected a JSON object' }, status => 400)
        unless ref($body) eq 'HASH';
    my $dilithium_key = $body->{dilithium_public_key};
    my $kyber_key     = $body->{kyber_public_key};

    return $self->render(json => { error => 'invalid public key encoding' }, status => 400)
        unless $self->_valid_pqc_keys($dilithium_key, $kyber_key);

    $self->pg->db->query(
        'UPDATE users SET dilithium_public_key = ?, kyber_public_key = ? WHERE id = ?',
        $dilithium_key, $kyber_key, $user->{id},
    );

    $self->render(json => { ok => 1 });
}

sub pqc_challenge ($self) {
    my $body = $self->req->json;
    return $self->render(json => { error => 'expected a JSON object' }, status => 400)
        unless ref($body) eq 'HASH';
    my $username = $body->{username} // '';
    return $self->render(json => { error => 'invalid username' }, status => 400)
        unless !ref($username) && length($username) && length($username) <= 128;
    
    my $user = $self->users->find_by_username($username);
    return $self->render(json => { error => 'user not found' }, status => 404)
        unless $user and $user->{dilithium_public_key};

    # Generate 32 raw bytes and Base64-encode for transport
    my $raw_nonce = random_bytes(32);
    my $nonce_b64 = MIME::Base64::encode_base64($raw_nonce, '');
    
    # Save it to the DB
    $self->pg->db->query(
        q{UPDATE users SET current_nonce = ?,
            pqc_nonce_expires_at = now() + interval '5 minutes' WHERE id = ?},
        $nonce_b64, $user->{id}
    );

    $self->render(json => { nonce => $nonce_b64 });
}

sub pqc_verify ($self) {
    my $body = $self->req->json;
    return $self->render(json => { error => 'expected a JSON object' }, status => 400)
        unless ref($body) eq 'HASH';
    my $username = $body->{username} // '';
    return $self->render(json => { error => 'invalid username' }, status => 400)
        unless !ref($username) && length($username) && length($username) <= 128;
    my $signature_b64 = $body->{signature} // '';
    return $self->render(json => { error => 'invalid signature encoding' }, status => 400)
        unless $self->pqc->valid_base64($signature_b64, 3309, 4627);

    my $ip = $self->client_ip;
    my $max = $self->auth_limits->{login_failures_per_15min} // 5;
    return $self->render(json => { error => 'too many attempts' }, status => 429)
        if $self->auth_attempts->recent_failures($ip, $username) >= $max;

    my $user = $self->users->find_by_username($username);
    return $self->render(json => { error => 'user not found' }, status => 404)
        unless $user and $user->{dilithium_public_key};

    my $nonce_b64 = $user->{current_nonce};
    return $self->render(json => { error => 'no challenge found' }, status => 400)
        unless $nonce_b64;

    my $public_key = $user->{dilithium_public_key};
    my $pqc = $self->pqc;
    return $self->render(json => { error => 'invalid registered public key' }, status => 401)
        unless $pqc->valid_base64($public_key, 1952, 2592) && $pqc->valid_base64($nonce_b64, 32);

    my $max_inflight = $self->auth_limits->{pqc_verifications_per_worker} // 4;
    if ($pqc_inflight >= $max_inflight) {
        $self->res->headers->header('Retry-After' => '1');
        return $self->render(json => { error => 'PQC verifier busy' }, status => 503);
    }
    ++$pqc_inflight;
    $self->render_later;
    Mojo::IOLoop->subprocess->run(
        sub { $pqc->verify($public_key, $nonce_b64, $signature_b64) },
        sub ($subprocess, $err, $valid = undef) {
            --$pqc_inflight;
            if ($err) {
                $self->app->log->error('Native PQC verification unavailable');
                return $self->render(json => { error => 'PQC verification unavailable' }, status => 503);
            }
            unless ($valid) {
                $self->auth_attempts->record_failure($ip, $username);
                return $self->render(json => { error => 'invalid signature' }, status => 401);
            }
            my $account = $self->pg->db->query(
                q{UPDATE users SET current_nonce = NULL, pqc_nonce_expires_at = NULL
                  WHERE id = ? AND current_nonce = ? AND dilithium_public_key = ?
                    AND pqc_nonce_expires_at > now() RETURNING id, username, role},
                $user->{id}, $nonce_b64, $public_key,
            )->hash;
            return $self->render(json => { error => 'challenge expired or already used' }, status => 401)
                unless $account;

            $self->auth_attempts->clear_failures($ip, $username);
            my $now = time;
            my $token = encode_jwt(
                payload => {
                    uid => $account->{id}, username => $account->{username},
                    role => $account->{role}, iat => $now, exp => $now + $COOKIE_MAX_AGE,
                },
                alg => 'HS256', key => $self->jwt_secret,
            );
            $self->_set_token_cookie($token);
            return $self->render(json => { ok => 1, username => $account->{username}, role => $account->{role} });
        },
    );
}

1;
