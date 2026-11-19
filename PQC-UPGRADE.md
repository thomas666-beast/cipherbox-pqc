# Cipherbox PQC Upgrade and Rollout

This upgrade connects the existing Vue and Perl application to the bundled hardened Cipherbox Rust source. It keeps the existing AES-GCM message and attachment formats so the new client can read old data without re-encrypting room history.

## What changed

- **Private rooms and invites:** The browser wraps the room key directly to the recipient’s registered public key and writes v2 envelopes. It still reads the original unversioned AES-GCM envelope and explicit Rust v1 or v2 envelopes without falling back after a failed authentication check.
- **PQC login:** The browser supports both ML-DSA-65 and ML-DSA-87 identities. Perl verifies signatures through the Rust executable outside the main event loop, caps concurrent verification per worker, and consumes a successful challenge exactly once. Challenges expire after five minutes.
- **Loading and database work:** Message history is cursor-paginated with a server-enforced page limit. Room-list previews use an indexed latest-message lookup per room instead of aggregating all messages. The browser imports the room’s AES key once per unlock for reuse; public joins no longer invoke the crypto executable. The room list itself is not paginated, and no production latency or throughput benchmark was run.
- **Attachments and downloads:** Private-room attachment uploads handle both in-memory and disk-backed multipart input, copying ciphertext in bounded chunks. Server-managed library downloads verify the entire AES-GCM tag before transmitting plaintext; temporary plaintext is staged on disk rather than held in one Perl buffer. Put the temp directory on a private, capacity-managed volume if your deployment handles sensitive library files.

## Rollout for an existing instance

1. **Back up before switching.** Take a consistent PostgreSQL and `storage/` backup, preserve the deployed `cipherbox.conf` and its existing `master_key`, and stage the release against a restored copy first. Keep the same browser origin and do not clear IndexedDB. Replacing a browser’s identity or regenerating its keys does not recover existing private-room access.
2. **Prepare the release.** Use the two sibling directories in this bundle. Install the toolchain as described in the app `README.md`, run `./build-crypto.sh`, and then run `npm ci` and `npm run build` in `frontend`. The build requires the matched wasm-bindgen CLI and uses the bundled Cargo lockfiles.
3. **Apply the database migration.** Stop app writers for the cutover. With the production DSN configured, run `carton exec ./script/migrate` from the app directory. On a large database, allow time for two indexes to build; this migration creates them transactionally and can block writes.
4. **Deploy API, verifier and frontend together.** Serve the new frontend assets, restart Perl, and have clients reload the application. Old frontend builds cannot open newly written v2 envelopes. Keep Perl on a private listener behind HTTPS, and have the trusted proxy replace incoming `X-Forwarded-For` with the real client address rather than passing user-supplied values through.
5. **Check before reopening writes.** From a staging browser with an existing identity, sign in and open a pre-upgrade room. Then register a new identity, invite it into a private room, send a message and an attachment, and page back through the room history. Check public joins and authenticated library downloads separately.

### Existing databases installed by running the schema SQL manually

The old README advised importing `001_full_schema.sql` directly. If you did that, the schema may already exist without a matching `schema_migrations` row. On a backup or staging restore, compare the schema to `migrations/001_full_schema.sql`, including extensions, tables, columns and indexes. Only after confirming that 001 is fully present, record that baseline under change control in the same database:

```sql
BEGIN;
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO schema_migrations (filename) VALUES ('001_full_schema.sql')
ON CONFLICT (filename) DO NOTHING;
COMMIT;
```

Then run `carton exec ./script/migrate` to apply 002. Do not mark a partial schema as applied or rerun the initial CREATE statements against an existing database. For a fresh, empty database, run the migration script directly without recording a baseline yourself.

### Rollback

Before enabling writes, make sure you can redeploy the prior release and restore the matching database and storage backups if needed. Once v2 envelopes have been written, rolling back only the old frontend leaves the affected rooms or invites unreadable to that client. Restoring a pre-upgrade database discards changes made after the snapshot; prefer a forward fix once the upgraded deployment accepts writes.

## Verification and limits

- **Checked locally:** The Rust native verifier and web WASM built, Vue built from the lockfile, and migrations applied and reran on a disposable PostgreSQL database. The real HTTP/WebSocket integration test passed modern and legacy fixture login, one-time challenge redemption under concurrency, private invites, encrypted chat, bounded history pages, public joins, and byte-exact decryption of two encrypted attachment sizes. The targeted Perl library test also confirmed integrity rejection after corrupting a stored tag.
- **Reproduce:** Point the sample `test` DSN at a disposable database and run `CIPHERBOX_ENV=test carton exec ./script/migrate`. Run `CIPHERBOX_ENV=test carton exec prove -l t/crypto.t t/download_stream.t t/health.t t/moderation_model.t` before starting the test daemon, because the test fixtures truncate tables. Then start `CIPHERBOX_ENV=test carton exec ./script/cipherbox daemon -l http://127.0.0.1:3000` and run `node --experimental-websocket frontend/tests/pqc-upgrade.mjs http://127.0.0.1:3000` from the app root. The Node test creates users and rooms; do not run it against production.
- **Incomplete coverage:** The full inherited Perl suite did not pass. Many fixtures still call password-based registration and use obsolete request shapes. Compatibility was tested using synthetic data, not real user records, and the Vue UI was compiled but not driven through a browser in these checks.
- **Dependencies:** `npm audit --omit=dev` returned zero findings after the lockfile update. The full npm audit still reported four entries from the same development-only `picomatch` advisory chain; the [GitHub Advisory Database entry](https://github.com/advisories/GHSA-fc5q-39xc-vjpf) is marked withdrawn. Keep build tooling private and re-check audit results before deployment.
- **Not implemented:** The app does not migrate chat to the Rust message ratchet, add verified per-message sender signatures, rotate static room keys on membership change, or provide forward secrecy for old AES-GCM room ciphertext. Public rooms and the server-managed library are not end-to-end encrypted. A hostile server serving modified JavaScript or replacement directory keys is outside what this release protects against.
