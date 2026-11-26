# PasswordNow

An open-source, zero-knowledge password manager for **macOS, Windows and Linux**,
with browser extensions for **Chrome, Edge, Brave and Firefox**, and end-to-end
encrypted sync between all your devices. You can use the hosted server or run
your own.

> ⚠️ **Status: early development. Do not store real passwords in it yet.**
> PasswordNow has not had an independent security audit. Until it has one, treat
> it as a learning and research project.

---

## Why PasswordNow is secure

### 1. Zero-knowledge: the server never sees your data

Encryption and decryption happen **only on your devices**. The sync server stores
encrypted blobs. It never learns your master password, your keys, or anything
inside your vault, including item titles and URLs.

If the server or its database is breached, the attacker gets ciphertext they
cannot decrypt.

### 2. Two secrets: the Master Password and the Secret Key

Your vault is protected by two things:

- **Master Password**: the one you remember.
- **Secret Key**: 128 random bits, generated on your device when you create
  your account. It is stored only on your devices and in your printed
  *Emergency Kit*. It is never sent to the server.

Both go into the key derivation. An attacker who steals the server database
can't brute-force your password even if it's weak, because each guess also
needs the 128-bit Secret Key, and 2¹²⁸ guesses can't be done.

### 3. Key hierarchy

```
Master Password + Secret Key
        │  Argon2id  (deliberately slow and memory-hard)
        ▼
   Master Key   (in RAM only, never stored)
        ├─ HKDF ─► Auth Key ──────► OPAQUE login to the server
        └─ HKDF ─► Key-Encryption Key
                        │ unwraps
                        ▼
                 Account Key (random, 256 bit)
                        │ unwraps
                        ▼
                 Vault Keys ─► Item Keys ─► your data
```

- **Argon2id** makes every password guess cost a lot of time and memory, which
  defeats GPU and ASIC cracking. The client enforces built-in **minimum
  parameters** and rejects weaker ones a server might send (downgrade
  protection).
- **Separate keys for login and encryption**: what the server sees during login
  can't be used to derive the encryption key.
- **Random data keys**: changing your Master Password only re-wraps the Account
  Key. Rotating vault keys after a device is revoked re-encrypts your data.

### 4. Login without sending your password: OPAQUE

We authenticate with **OPAQUE** (RFC 9807), an asymmetric password-authenticated
key exchange. Neither your password nor anything equivalent to it is ever sent
to the server. A server-side database leak alone does not allow an offline
attack.

### 5. Authenticated encryption everywhere

Every item is encrypted with **XChaCha20-Poly1305** (AEAD) under its own key. The
item ID, vault ID and revision are bound as *associated data*. Any modification,
swap or replay of a ciphertext is detected and rejected.

**Core rule:** everything a client *acts on* must be authenticated with a key the
server does not have. That covers items, deletions ("tombstones" are encrypted
revisions, not plaintext flags) and the list of trusted devices. A malicious
server can't wipe, roll back or inject data without being detected.

### 6. The browser extension is deliberately "dumb"

The extension holds **no keys**. It talks to the desktop app over the browser's
**Native Messaging** channel. The desktop app:

- releases **one** credential per request, **only for the exact current host**,
  and only after a real user action;
- refuses bulk queries and locks itself on suspicious request patterns;
- verifies **which process** is connecting, using OS peer credentials and code
  signatures, so other local programs can't impersonate the extension.

Even a compromised extension can't dump your vault.

### 7. Safe autofill

- Autofill matches the **exact host** by default. `wiki.example.com` does not
  get the credentials for `login.example.com` unless you allow it for that
  item.
- Nothing is filled without a user action. No filling into cross-origin iframes
  or over plain `http://` without explicit confirmation.
- The autofill UI is isolated from the web page (clickjacking protection).

### 8. Adding a new device

The **new** device shows a QR code that contains only a fresh *public* key. Your
already unlocked device scans it. Both screens then show a short confirmation
code, and you approve on the trusted device. Only then is the Secret Key sent,
encrypted to the new device's key. Someone scanning the QR code over your
shoulder gets nothing secret.

For devices without a camera, there is a short one-time code (PAKE-based, like
magic-wormhole).

### 9. Local protection

- Auto-lock on timeout, screen lock and sleep.
- Keys are wiped from memory after use (`zeroize`) and kept out of swap.
- Biometric unlock (Touch ID, Windows Hello, Secret Service) stores a
  device-bound unlock key in the OS keystore, **never your Master Password**.
- The clipboard is cleared automatically after 30 seconds.

### 10. No backdoors, no "reset password" email

We can't reset your Master Password, and that's by design: a backdoor for us
would also be a backdoor for attackers. Keep your Emergency Kit safe. You can
also create an offline **recovery code**.

---

## Threat model (summary)

| Attacker | Protection |
|---|---|
| Steals the server database | Zero-knowledge, Secret Key, Argon2id |
| Intercepts network traffic | TLS 1.3, end-to-end encryption, OPAQUE |
| Malicious or compromised server | AEAD with associated data; authenticated tombstones and device list; client-enforced KDF minimums |
| Phishing website | Exact-host autofill matching |
| XSS on a sibling subdomain | Exact-host matching by default |
| Malicious or hijacked extension update | Keyless extension; one credential per user action; no bulk access |
| Local process impersonating the extension | Peer-credential and code-signature checks on the native messaging bridge |
| Stolen locked laptop | Encryption at rest, auto-lock, Argon2id |
| Compromised build or update pipeline | Offline signing keys, hardware 2FA, Chrome *Verified CRX Uploads*, pinned CI actions, reproducible builds |
| **Out of scope** | Malware with full control of your machine *while the vault is unlocked*. No password manager can defend against that. |

The full analysis will be in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Architecture

```
            ┌──────────────────────────────────────────────────────┐
            │               Rust core  (pwn-core)                  │
            │   crypto · vault model · sync logic · import/export  │
            └───────┬──────────────────┬──────────────────┬────────┘
                    │ pwn-ffi          │ pwn-wasm         │
                    │ (cxx bridge)     │                  │
  ┌─────────────────▼──────────┐  Extension popup   Sync server (Rust)
  │ Desktop app (C++20, Qt 6)  │  Leptos → WASM     axum + sqlx
  │  UI: Qt Quick (QML)        │       │            PostgreSQL
  │  pwn-platform: keystore,   │       │
  │  biometrics, mlock,        │       │
  │  lock events, clipboard    │       │
  └─────────────────▲──────────┘       │
                    │ local socket / named pipe (both ends verified)
             pwn-host (C++)  native messaging relay
                    ▲
                    │ stdin/stdout (Native Messaging)
  Browser extension ┘ (+ small TypeScript content script for autofill)
```

| Component | Language | Technology |
|---|---|---|
| Core library | Rust | RustCrypto, `argon2`, `chacha20poly1305`, `opaque-ke`, `zeroize` |
| Core ↔ C++ bridge | Rust + C++ | [`cxx`](https://cxx.rs), built from CMake via [Corrosion](https://github.com/corrosion-rs/corrosion) |
| Desktop app | C++20 + QML | Qt 6 (Qt Quick / QML), CMake |
| Platform layer | C++20 | OS keystores (Keychain, Windows Hello, Secret Service), memory locking, screen-lock events, clipboard |
| Native messaging host | C++20 | CMake. A thin relay between browser and desktop app. |
| Browser extension | Rust + TS | Manifest V3; popup in Leptos/WASM, minimal TypeScript content script |
| Sync server | Rust | axum, sqlx, plain PostgreSQL. It runs on any Postgres, managed or self-hosted, and uses no vendor-specific features. |
| Local storage | Rust | SQLite with encrypted items |

### Why Rust *and* C++?

- **All security-critical logic is Rust only**: cryptography, key handling, the
  vault format, parsing of any untrusted data (sync responses, imports), and the
  sync protocol. Rust's memory safety rules out whole classes of bugs (buffer
  overflows, use-after-free) by construction.
- **Keys never cross into C++.** The desktop UI asks the core to *perform*
  operations ("unlock", "decrypt item 42", "copy password of item 42"). It only
  receives the decrypted fields it has to display, wrapped in a
  self-wiping `SecretBuffer`.
- **C++ is used for the UI and thin OS-integration layers**, where the native
  APIs (Qt, Win32, POSIX, Apple frameworks) are C/C++ anyway. These layers **don't
  interpret untrusted data**. For example, `pwn-host` forwards length-limited
  messages without parsing them, and the Rust side does all validation.
- **No web engine in the desktop app.** The UI is Qt Quick (QML), not HTML in a
  webview. All QML is compiled into the binary (`qt_add_qml_module`, `qmlsc`);
  nothing is ever loaded from the network or from user data. Every text element
  showing user data is forced to `Text.PlainText`, so Qt never interprets it as
  rich text.
- **Secrets stay out of the QML/JavaScript engine where possible.** QML strings
  live in a garbage-collected heap that can't be reliably wiped. Passwords are
  masked by default, and copy-to-clipboard runs entirely in C++ straight from a
  `SecretBuffer`. The password only enters QML when you explicitly reveal it.
- The C++ code is held to a strict standard: modern C++20 (RAII, no raw
  `new`/`delete`), `-Wall -Wextra -Werror`, compiler hardening flags,
  AddressSanitizer/UBSan in CI, `clang-tidy`, and fuzzing of every input path.

### Repository layout (planned)

```
passwordnow/
├── crates/
│   ├── pwn-core/      # Rust: crypto, data model, sync logic (no I/O)
│   ├── pwn-storage/   # Rust: local SQLite storage
│   ├── pwn-ffi/       # Rust: cxx bridge exposing the core to C++
│   ├── pwn-server/    # Rust: sync server
│   └── pwn-wasm/      # Rust: WASM bindings for the extension
├── native/
│   ├── pwn-host/      # C++: native messaging host
│   └── pwn-platform/  # C++: OS integration library
├── apps/
│   ├── desktop/       # C++/Qt desktop app (CMake)
│   └── extension/     # browser extension
└── docs/
    ├── ARCHITECTURE.md
    ├── THREAT_MODEL.md
    └── CRYPTO_SPEC.md
```

---

## Roadmap

- [ ] **Phase 0: Specification**: crypto spec, versioned data formats, threat model
- [ ] **Phase 1: Core**: key derivation, encryption, data model, test vectors, fuzzing
- [ ] **Phase 2: Desktop (offline, Qt)**: Rust↔C++ bridge, create vault, manage items, password generator, auto-lock
- [ ] **Phase 3: Browser extension**: native messaging, pairing, autofill, save prompts
- [ ] **Phase 4: Sync**: server, OPAQUE login, push/pull, conflict resolution, device management
- [ ] **Phase 5: Comfort**: biometrics, QR device linking, imports, TOTP, passkeys
- [ ] **Phase 6: Hardening**: external audit, bug bounty, reproducible builds
- [ ] **Later**: iOS/Android (same Rust core), shared vaults, Safari

---

## Building

Requires [Rust](https://rustup.rs), [CMake](https://cmake.org) ≥ 3.25, a
C++20 compiler (Clang, GCC or MSVC) and [Qt 6](https://www.qt.io/download-open-source).

Rust parts:

```bash
cargo build
cargo test
```

C++ parts (example: the desktop app, which also builds the Rust core it links):

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

---

## Security

Please **do not** report vulnerabilities in public issues. Use GitHub's
*private vulnerability reporting* (Security tab → "Report a vulnerability").

## Contributing

Contributions are welcome. Cryptographic changes need a written rationale and
test vectors. We never implement cryptographic primitives ourselves; we only
use well-reviewed libraries.

## License

PasswordNow is free software, licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE)
(`AGPL-3.0-or-later`).

You may use, study, modify and share it. If you distribute a modified version,
**or run a modified version of the server for other people over a network**, you
must publish your changes under the same license.
