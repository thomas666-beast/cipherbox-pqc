use Mojo::Base -strict;
use Test::Mojo;
use Test::More;
use Mojo::File 'path';
use File::Temp qw(tempfile);
use Crypt::JWT qw(encode_jwt);
use lib 't/lib';
use TestSetup;

my $t = Test::Mojo->new('Cipherbox');
setup_test_db($t->app);
my $admin = $t->app->pg->db->query(
    "INSERT INTO users (username, role) VALUES ('fixture_admin', 'admin') RETURNING id"
)->hash;
my $admin_token = encode_jwt(
    payload => { uid => $admin->{id}, exp => time + 60 },
    alg => 'HS256', key => $t->app->jwt_secret,
);

$t->post_ok('/api/library/categories' => { Authorization => "Bearer $admin_token" } => json => {
    name => 'Big', type => 'video',
})->status_is(200);
my $cat_id = $t->tx->res->json->{category}{id};

# 1 MiB of random-ish data
my $big = join('', map { chr(($_ * 37 + 11) % 256) } 1 .. 1_048_576);
my ($fh, $temp) = tempfile(UNLINK => 1);
binmode $fh;
print {$fh} $big or die "Unable to write test file: $!";
close $fh or die "Unable to close test file: $!";

$t->post_ok('/api/library/items' => { Authorization => "Bearer $admin_token" } => form => {
    title       => 'Big file',
    category_id => $cat_id,
    file        => { file => $temp, filename => 'big.bin', 'content-type' => 'application/octet-stream' },
})->status_is(200);
my $item_id = $t->tx->res->json->{item}{id};

# Download and verify byte-for-byte
$t->get_ok("/api/library/items/$item_id/download" => { Authorization => "Bearer $admin_token" })
   ->status_is(200)->header_is('Cache-Control' => 'private, no-store');
my $got = $t->tx->res->content->asset->slurp;
utf8::encode($got) if utf8::is_utf8($got);
is length($got), length($big), 'downloaded size matches';
ok $got eq $big, 'downloaded bytes match original';

my $stored_name = $t->app->pg->db->query(
    'SELECT file_path FROM library_items WHERE id = ?', $item_id
)->hash->{file_path};
my $stored = path($t->app->home, 'storage', 'library', $stored_name);
CORE::open(my $blob, '+<:raw', $stored) or die "Unable to open fixture: $!";
seek($blob, -1, 2) or die "Unable to locate fixture tag: $!";
read($blob, my $last, 1) == 1 or die "Unable to read fixture tag";
seek($blob, -1, 2) or die "Unable to locate fixture tag: $!";
print {$blob} chr(ord($last) ^ 1) or die "Unable to corrupt fixture tag: $!";
close $blob or die "Unable to close fixture: $!";
$t->get_ok("/api/library/items/$item_id/download" => { Authorization => "Bearer $admin_token" })
  ->status_is(500)->json_is({ error => 'file could not be authenticated' });

$stored->remove;

my ($small_fh, $small_path) = tempfile(UNLINK => 1);
binmode $small_fh;
my $small = "\0small file\xff";
print {$small_fh} $small or die "Unable to write test file: $!";
close $small_fh or die "Unable to close test file: $!";
$t->post_ok('/api/library/items' => { Authorization => "Bearer $admin_token" } => form => {
    title => 'Small file', category_id => $cat_id,
    file => { file => $small_path, filename => 'small.bin', 'content-type' => 'application/octet-stream' },
})->status_is(200);
my $small_id = $t->tx->res->json->{item}{id};
$t->get_ok("/api/library/items/$small_id/download" => { Authorization => "Bearer $admin_token" })
   ->status_is(200)->content_is($small);
my $small_stored = $t->app->pg->db->query('SELECT file_path FROM library_items WHERE id = ?', $small_id)->hash;
path($t->app->home, 'storage', 'library', $small_stored->{file_path})->remove;

teardown_test_db($t->app);
done_testing();
