package Cipherbox::Controller::Paste;
use Mojo::Base 'Mojolicious::Controller', -signatures;
use Mojo::File 'path';
use UUID::Tiny qw(create_uuid_as_string UUID_V4);

sub _storage_dir ($self) {
    my $dir = path($self->app->home, 'storage', 'pastes');
    $dir->make_path unless -d $dir;
    return $dir;
}

sub _resolve_room ($self, $param) {
    return $self->rooms->find_by_hash_or_id($param);
}

sub _paste_json ($paste) {
    return {
        id          => $paste->{id},
        public_hash => $paste->{public_hash},
        title       => $paste->{title},
        kind        => $paste->{kind},
        file_name   => $paste->{file_name},
        file_size   => $paste->{file_size},
        mime_type   => $paste->{mime_type},
        deleted_at  => $paste->{deleted_at},
    };
}

sub create ($self) {
    my $user = $self->current_user;
    my $room = $self->_resolve_room($self->param('room_id'));
    return $self->render(json => { error => 'room not found' }, status => 404)
        unless $room;

    my $role = $self->rooms->member_role($room->{id}, $user->{id});
    return $self->render(json => { error => 'forbidden' }, status => 403)
        unless $role;

    my $title = $self->param('title') // '';
    return $self->render(json => { error => 'missing title' }, status => 400)
        unless length $title;

    my $wrapped_ct  = $self->param('wrapped_key_ct');
    my $wrapped_iv  = $self->param('wrapped_key_iv');
    my $wrapped_tag = $self->param('wrapped_key_tag');
    
    return $self->render(json => { error => 'missing wrapped key' }, status => 400)
        unless $wrapped_ct and $wrapped_iv and $wrapped_tag;

    my $file = $self->req->upload('file');
    my $text_ct = $self->param('content_ct');

    if ($file) {
        return $self->_create_file_paste($user, $room, $title, $file, $wrapped_ct, $wrapped_iv, $wrapped_tag);
    }
    if ($text_ct) {
        return $self->_create_text_paste($user, $room, $title, $text_ct, $wrapped_ct, $wrapped_iv, $wrapped_tag);
    }
    return $self->render(json => { error => 'no text or file' }, status => 400);
}

sub _create_text_paste ($self, $user, $room, $title, $text_ct, $wrapped_ct, $wrapped_iv, $wrapped_tag) {
    my $paste = $self->pastes->create_text(
        room_id               => $room->{id},
        sender_id             => $user->{id},
        title                 => $title,
        content_encrypted     => $text_ct,
        content_iv            => $self->param('content_iv'),
        content_tag           => $self->param('content_tag'),
        wrapped_key_encrypted => $wrapped_ct,
        wrapped_key_iv        => $wrapped_iv,
        wrapped_key_tag       => $wrapped_tag,
    );

    $self->render(json => { paste => _paste_json($paste) });
}

sub _create_file_paste ($self, $user, $room, $title, $file, $wrapped_ct, $wrapped_iv, $wrapped_tag) {
    my $max_size   = $self->config->{storage}{max_paste_size} // 10485760;
    my $chunk_size = $self->config->{storage}{chunk_size}     // 65536;

    my $size = $file->size // 0;
    return $self->render(json => { error => "file too large (max " . ($max_size / 1024 / 1024) . " MB)" }, status => 400)
        if $size > $max_size;

    return $self->render(json => { error => 'invalid encrypted file' }, status => 400)
        if $size < 28;

    my $uuid = create_uuid_as_string(UUID_V4);
    my $stored_path = $self->_storage_dir->child("$uuid.bin");
    my $mime  = $self->param('mime_type') // 'application/octet-stream';
    my $fname = $self->param('file_name') // 'file';

    my $paste = eval {
        die 'invalid configured chunk size' unless $chunk_size > 0;
        CORE::open(my $fh, '>:raw', $stored_path) or die "Cannot open attachment: $!";
        # Preserve IV || tag || ciphertext. Mojo may keep small uploads in memory.
        my $asset = $file->asset;
        for (my $offset = 0; $offset < $size;) {
            my $chunk = $asset->get_chunk($offset, $chunk_size);
            die 'Cannot read complete attachment' unless defined($chunk) && length($chunk);
            print {$fh} $chunk or die "Cannot write attachment: $!";
            $offset += length($chunk);
        }
        close $fh or die "Cannot close attachment: $!";
        $self->pastes->create_file(
            room_id               => $room->{id},
            sender_id             => $user->{id},
            title                 => $title,
            mime_type             => $mime,
            file_name             => $fname,
            file_size             => $size,
            file_path             => "$uuid.bin",
            wrapped_key_encrypted => $wrapped_ct,
            wrapped_key_iv        => $wrapped_iv,
            wrapped_key_tag       => $wrapped_tag,
        );
    };
    unless ($paste) {
        $self->app->log->error('Could not store encrypted room attachment');
        unlink $stored_path;
        return $self->render(json => { error => 'could not store attachment' }, status => 500);
    }

    $self->render(json => { paste => _paste_json($paste) });
}

sub open ($self) {
    my $user = $self->current_user;
    my $paste = $self->pastes->find_by_hash($self->param('hash'));
    return $self->render(json => { error => 'not found' }, status => 404) unless $paste;
    return $self->render(json => { error => 'forbidden' }, status => 403)
        unless $self->rooms->is_member($paste->{room_id}, $user->{id});
    return $self->render(json => { error => 'deleted' }, status => 410) if $paste->{deleted_at};

    $self->render(json => {
        paste => {
            %{ _paste_json($paste) },
            content_encrypted     => $paste->{content_encrypted},
            content_iv            => $paste->{content_iv},
            content_tag           => $paste->{content_tag},
            wrapped_key_encrypted => $paste->{wrapped_key_encrypted},
            wrapped_key_iv        => $paste->{wrapped_key_iv},
            wrapped_key_tag       => $paste->{wrapped_key_tag},
        },
    });
}

sub download ($self) {
    my $user = $self->current_user;
    my $paste = $self->pastes->find_by_hash($self->param('hash'));
    return $self->render(json => { error => 'not found' }, status => 404) unless $paste;
    return $self->render(json => { error => 'forbidden' }, status => 403)
        unless $self->rooms->is_member($paste->{room_id}, $user->{id});
    return $self->render(json => { error => 'deleted' }, status => 410) if $paste->{deleted_at};
    return $self->render(json => { error => 'not a file' }, status => 400)
        unless $paste->{kind} eq 'file';

    my $stored = $self->_storage_dir->child($paste->{file_path});
    return $self->render(json => { error => 'file missing' }, status => 500)
        unless -e $stored;

    # Stream the encrypted file directly to the browser (the browser will decrypt it)
    $self->res->headers->content_type('application/octet-stream');
    my $safe = $paste->{file_name} // 'file';
    $safe =~ s/[\x00-\x1f\x7f]/_/g;
    $safe =~ s/(["\\])/\\$1/g;
    $self->res->headers->content_disposition('attachment; filename="' . $safe . '"');
    $self->res->headers->cache_control('private, no-store');
    $self->reply->file($stored);
}

1;
