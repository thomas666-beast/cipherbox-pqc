package Cipherbox::Controller::Library;
use Mojo::Base 'Mojolicious::Controller', -signatures;
use Mojo::File 'path';
use Mojo::Asset::File;
use UUID::Tiny qw(create_uuid_as_string UUID_V4);
use Crypt::AuthEnc::GCM;
use MIME::Base64 ();
use Crypt::PRNG qw(random_bytes);

sub _storage_dir ($self) {
    my $dir = path($self->app->home, 'storage', 'library');
    $dir->make_path unless -d $dir;
    return $dir;
}

sub _is_admin ($self) {
    my $u = $self->current_user;
    return $u && ($u->{role} // '') eq 'admin';
}

sub _resolve_category ($self, $param) {
    return $self->library->find_category_by_hash_or_id($param);
}

sub _resolve_item ($self, $param) {
    return $self->library->find_item_by_hash_or_id($param);
}

# ==========================================
# CATEGORIES
# ==========================================

sub list_categories ($self) {
    my $parent = $self->param('parent_id');
    my $parent_id;
    if (defined $parent and length $parent) {
        my $cat = $self->_resolve_category($parent);
        return $self->render(json => { error => 'parent not found' }, status => 404)
            unless $cat;
        $parent_id = $cat->{id};
    }
    my $list = $self->library->list_categories($parent_id);
    $self->render(json => { categories => $list });
}

sub get_category ($self) {
    my $param = $self->param('id');
    my $cat = $self->_resolve_category($param);
    return $self->render(json => { error => 'not found' }, status => 404)
        unless $cat;
    $self->render(json => { category => $cat });
}

sub create_category ($self) {
    return $self->render(json => { error => 'forbidden' }, status => 403)
        unless $self->_is_admin;

    my $body   = $self->req->json;
    my $name   = $body->{name} // '';
    my $type   = $body->{type} // '';
    my $parent = $body->{parent_id};

    return $self->render(json => { error => 'missing fields' }, status => 400)
        unless length $name and length $type;
    return $self->render(json => { error => 'bad type' }, status => 400)
        unless $type =~ /^(book|audio|video)$/;

    my $parent_id;
    if (defined $parent and length $parent) {
        my $p = $self->_resolve_category($parent);
        return $self->render(json => { error => 'parent not found' }, status => 404)
            unless $p;
        $parent_id = $p->{id};
    }

    my $cat = eval { $self->library->create_category($name, $type, $parent_id) };
    if ($@) {
        return $self->render(json => { error => "create failed: $@" }, status => 500);
    }

    $self->render(json => { category => $cat });
}

sub delete_category ($self) {
    return $self->render(json => { error => 'forbidden' }, status => 403)
        unless $self->_is_admin;

    my $param = $self->param('id');
    my $cat = $self->_resolve_category($param);
    return $self->render(json => { error => 'not found' }, status => 404)
        unless $cat;

    # Collect the full subtree of category ids
    my $rows = $self->pg->db->query(
        q{
            WITH RECURSIVE subtree AS (
                SELECT id FROM library_categories WHERE id = ?
                UNION ALL
                SELECT c.id FROM library_categories c
                JOIN subtree s ON c.parent_id = s.id
            )
            SELECT id FROM subtree
        },
        $cat->{id},
    )->arrays;

    my @cat_ids = map { $_->[0] } @$rows;
    return $self->render(json => { ok => 1, deleted => 0 }) unless @cat_ids;

    # Collect all file paths from items in those categories
    my $placeholders = join ',', ('?') x @cat_ids;
    my $files = $self->pg->db->query(
        "SELECT file_path FROM library_items WHERE category_id IN ($placeholders)",
        @cat_ids,
    )->hashes;

    for my $item (@$files) {
        next unless $item->{file_path};
        my $f = $self->_storage_dir->child($item->{file_path});
        $f->remove if -e $f;
    }

    # Delete the top category — DB cascade handles children and items
    $self->library->delete_category($cat->{id});

    $self->render(json => { ok => 1, deleted_categories => scalar(@cat_ids) });
}

sub tree ($self) {
    my $tree = $self->library->tree;
    $self->render(json => { tree => $tree });
}

# ==========================================
# ITEMS (FILES)
# ==========================================

sub list_items ($self) {
    my $param = $self->param('id');
    my $cat = $self->_resolve_category($param);
    return $self->render(json => { error => 'category not found' }, status => 404)
        unless $cat;

    my $cfg    = $self->pagination;
    my $limit  = $self->param('limit')  // $cfg->{default_limit};
    my $offset = $self->param('offset') // 0;
    $limit = $cfg->{max_limit} if $limit > $cfg->{max_limit};
    $limit = 1 if $limit < 1;
    $offset = 0 if $offset < 0;

    my $items = $self->library->list_items($cat->{id}, $limit, $offset);
    $self->render(json => {
        items  => $items,
        limit  => $limit,
        offset => $offset,
    });
}

sub upload_item ($self) {
    return $self->render(json => { error => 'forbidden' }, status => 403)
        unless $self->_is_admin;

    my $title       = $self->param('title')       // '';
    my $category_in = $self->param('category_id') // '';
    my $file        = $self->req->upload('file');

    return $self->render(json => { error => 'missing title' }, status => 400)
        unless length $title;
    return $self->render(json => { error => 'missing category' }, status => 400)
        unless $category_in;
    return $self->render(json => { error => 'no file' }, status => 400)
        unless $file;

    my $cat = $self->_resolve_category($category_in);
    return $self->render(json => { error => 'category not found' }, status => 404)
        unless $cat;

    my $max_size   = $self->config->{storage}{max_upload_size} // 104857600;
    my $chunk_size = $self->config->{storage}{chunk_size}      // 65536;

    my $size = $file->size // 0;
    return $self->render(json => { error => "file too large (max " . ($max_size / 1024 / 1024) . " MB)" }, status => 400)
        if $size > $max_size;

    my $uuid     = create_uuid_as_string(UUID_V4);
    my $file_key = $self->crypto->generate_room_key;
    my $wrapped  = $self->crypto->wrap_room_key($file_key);

    my $raw_key  = MIME::Base64::decode_base64($file_key);
    my $iv       = random_bytes(12);
    
    my $stored_path = $self->_storage_dir->child("$uuid.bin");

    my $mime  = $file->headers->content_type // 'application/octet-stream';

    my $item = eval {
        die 'invalid configured chunk size' unless $chunk_size > 0;
        CORE::open(my $fh, '>:raw', $stored_path) or die "Cannot open library item: $!";
        print {$fh} $iv or die "Cannot write IV: $!";
        my $ae = Crypt::AuthEnc::GCM->new('AES', $raw_key, $iv);
        my $asset = $file->asset;
        for (my $offset = 0; $offset < $size;) {
            my $chunk = $asset->get_chunk($offset, $chunk_size);
            die 'Cannot read complete library upload' unless defined($chunk) && length($chunk);
            print {$fh} $ae->encrypt_add($chunk) or die "Cannot write ciphertext: $!";
            $offset += length($chunk);
        }
        print {$fh} $ae->encrypt_done or die "Cannot write authentication tag: $!";
        close $fh or die "Cannot close library item: $!";
        $self->library->create_item(
            category_id        => $cat->{id},
            title              => $title,
            file_path          => "$uuid.bin",
            file_key_encrypted => $wrapped,
            mime_type          => $mime,
            uploaded_by        => $self->current_user->{id},
            file_size          => $size,
            uuid               => $uuid,
        );
    };
    unless ($item) {
        $self->app->log->error('Could not store encrypted library item');
        unlink $stored_path;
        return $self->render(json => { error => 'upload failed' }, status => 500);
    }

    $self->render(json => {
        item => {
            id          => $item->{id},
            public_hash => $item->{public_hash},
            category_id => $item->{category_id},
            title       => $item->{title},
            mime_type   => $item->{mime_type},
            file_size   => $item->{file_size},
        },
    });
}

sub download_item ($self) {
    my $param = $self->param('id');
    my $item = $self->_resolve_item($param);
    return $self->render(json => { error => 'not found' }, status => 404)
        unless $item;

    my $stored_path = $self->_storage_dir->child($item->{file_path});
    return $self->render(json => { error => 'file missing' }, status => 500)
        unless -e $stored_path;

    my $chunk_size = $self->config->{storage}{chunk_size} // 65536;

    CORE::open(my $fh, '<:raw', $stored_path) or
        return $self->render(json => { error => 'open failed' }, status => 500);

    # Authenticate the complete legacy AES-GCM blob before handing any
    # plaintext to the response. Stage it in a private, bounded-memory asset.
    my $staged = eval {
        my $remaining = (-s $fh) - 28;
        die "invalid encrypted file size" if $remaining < 0 || $chunk_size < 1;
        my ($iv, $tag);
        die "invalid file framing"
            unless (read($fh, $iv, 12) // 0) == 12
                && seek($fh, -16, 2) && (read($fh, $tag, 16) // 0) == 16
                && seek($fh, 12, 0);
        my $file_key = $self->crypto->unwrap_room_key($item->{file_key_encrypted});
        my $ae = Crypt::AuthEnc::GCM->new('AES', MIME::Base64::decode_base64($file_key), $iv);
        my $asset = Mojo::Asset::File->new;
        # On POSIX, avoid leaving a named plaintext file even on a worker crash.
        if ($^O ne 'MSWin32') {
            $asset->handle;
            unlink $asset->path or die "Could not unlink download spool: $!";
        }
        while ($remaining > 0) {
            my $want = $remaining > $chunk_size ? $chunk_size : $remaining;
            my $got = read($fh, my $buf, $want);
            die "could not read encrypted file" unless $got;
            $asset->add_chunk($ae->decrypt_add($buf));
            $remaining -= $got;
        }
        die "file did not authenticate" unless $ae->decrypt_done($tag);
        $asset;
    };
    close $fh;
    return $self->render(json => { error => 'file could not be authenticated' }, status => 500)
        unless $staged;

    $self->res->headers->content_type($item->{mime_type} // 'application/octet-stream');
    my $safe_title = $item->{title};
    $safe_title =~ s/[\x00-\x1f\x7f]/_/g;
    $safe_title =~ s/(["\\])/\\$1/g;
    $self->res->headers->content_disposition('attachment; filename="' . $safe_title . '"');
    $self->res->headers->cache_control('private, no-store');
    $self->res->content->asset($staged);
    $self->rendered(200);
}

sub delete_item ($self) {
    return $self->render(json => { error => 'forbidden' }, status => 403)
        unless $self->_is_admin;
    my $param = $self->param('id');
    my $item = $self->_resolve_item($param);
    return $self->render(json => { error => 'not found' }, status => 404)
        unless $item;

    my $stored = $self->_storage_dir->child($item->{file_path});
    $stored->remove if -e $stored;

    $self->library->delete_item($item->{id});
    $self->render(json => { ok => 1 });
}

sub rename_item ($self) {
    return $self->render(json => { error => 'forbidden' }, status => 403)
        unless $self->_is_admin;

    my $param = $self->param('id');
    my $body  = $self->req->json;
    my $title = $body->{title} // '';

    return $self->render(json => { error => 'missing title' }, status => 400)
        unless length $title;

    my $item = $self->_resolve_item($param);
    return $self->render(json => { error => 'not found' }, status => 404)
        unless $item;

    $self->library->update_item_title($item->{id}, $title);
    $self->render(json => { ok => 1, title => $title });
}

1;
