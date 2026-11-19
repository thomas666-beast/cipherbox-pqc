# Cipherbox PQC

Cipherbox is a self-hosted chat and file-sharing application with a Vue client, a Perl/Mojolicious API and WebSocket server, and PostgreSQL. The browser uses the bundled Rust crypto through WebAssembly. The Perl service uses a Rust executable for account-signature verification.

See [Cipherbox PQC Upgrade and Rollout](PQC-UPGRADE.md) before deploying to an existing instance.

## Local setup

Use a current stable Rust toolchain with the `wasm32-unknown-unknown` target, Perl 5.30+ with Carton and PostgreSQL 14+, and Node.js 20.19+ or 22.12+. The source bundle contains sibling `cipherbox-pqc` (app) and `cipherbox` (Rust) directories.

```bash
cd cipherbox-pqc
carton install
cp cipherbox.conf.example cipherbox.conf
# Set the database DSN and real secrets before starting a shared instance.
carton exec ./script/migrate
rustup target add wasm32-unknown-unknown
cargo install --locked wasm-bindgen-cli --version 0.2.130
./build-crypto.sh
cd frontend
npm ci
npm run build
```

For local development, run `carton exec ./script/cipherbox daemon -l http://127.0.0.1:3000` from the app root and `npm run dev` from `frontend` in a second terminal. Open the Vite address at `http://localhost:5173`; the development proxy forwards `/api` and `/chat` to Perl. The first registered account on an empty database receives the admin role, so provision it before opening registration to others.

For production, serve `frontend/dist` from the HTTPS origin with SPA fallback, and proxy `/api`, `/chat` (including WebSocket upgrades) and optionally `/health` to the Perl service on a private listener. Never expose the Vite development server publicly.

## Security boundary

New identities use hybrid X25519 + ML-KEM-1024 for key wrapping and ML-DSA-87 for login. Existing supported PQC identities and room-key envelopes remain readable. Private-room message and attachment content is still encrypted in the browser with AES-GCM; titles, filenames, membership, and other metadata are not necessarily encrypted. Public-room keys and library decryption are server-managed.

An account-login signature does not sign chat messages. This web app does not yet use the Rust chat ratchet or verify chat sender keys independently, and the server supplies both the web client and the recipient key directory. It is not an independently audited, zero-trust chat system.
