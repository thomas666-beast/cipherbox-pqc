package Cipherbox::PQC;
use Mojo::Base -base, -signatures;
use MIME::Base64 qw(decode_base64 encode_base64);

has verifier => undef;

sub valid_base64 ($self, $value, @sizes) {
    return 0 if !defined($value) || ref($value);
    return 0 unless grep { length($value) == 4 * int(($_ + 2) / 3) } @sizes;
    return 0 unless $value =~ /\A[A-Za-z0-9+\/]+={0,2}\z/;
    my $bytes = decode_base64($value);
    return 0 unless grep { length($bytes) == $_ } @sizes;
    return encode_base64($bytes, '') eq $value;
}

sub verify ($self, $public_key, $nonce, $signature) {
    my $bin = $self->verifier;
    die "Native PQC verifier is unavailable\n" unless defined($bin) && -f $bin && -x _;
    CORE::open(my $pipe, '-|', $bin, $public_key, $nonce, $signature)
        or die "Could not start native PQC verifier\n";
    my $result = <$pipe> // '';
    my $closed = close $pipe;
    my $status = $?;
    return 1 if $closed && $result eq "true\n";
    return 0 if $status == (1 << 8) && $result eq "false\n";
    die "Unexpected native PQC verifier result\n";
}

1;
