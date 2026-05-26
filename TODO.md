# TODO

Code review findings, ranked by severity.

## High

- **`src/main.rs:453` — Private key not zeroized on early-exit paths**
  `composite_priv` holds the raw ML-KEM + X25519 private key as a plain `Vec<u8>`. Three
  paths exit without reaching the `composite_priv.zeroize()` call on line 478: password
  mismatch, empty password, and `encrypt_private_key` failure. Wrap in `SensitiveData` or
  use a `scopeguard`/`defer!` to guarantee zeroization on all paths.

## Medium

- **`src/main.rs:690` — No cleanup of partial encrypted output on write failure**
  `decrypt_file` uses `TempFileGuard` to clean up on failure; `encrypt_file` does not. If a
  write fails mid-encryption (disk full, I/O error), a partial `.enc` file remains at
  `output_path`, and the next run fails with "already exists" until manually deleted. Write
  to a temp path with a `TempFileGuard` and rename to the final path on success.

- **`src/main.rs:882` — `MlKem1024PrivateKey` has no `ZeroizeOnDrop`; key bytes persist after decapsulation**
  `[u8; 3168]` is `Copy`, so `MlKem1024PrivateKey::from(mlkem_sk_array)` copies the bytes
  into the struct. The `mlkem_sk_array.zeroize()` call on line 883 only zeroes the local
  stack variable. libcrux-ml-kem derives no drop handler, so the private key bytes live in
  memory until the stack frame is recycled. File an upstream request to implement
  `ZeroizeOnDrop`, or manually overwrite via `as_slice_mut` before dropping.

## Low

- **`src/main.rs:1005` — Decrypted temp file leaks to an unknown path on rename failure**
  `temp_guard.disarm()` is called before `fs::rename`. If rename fails (cross-device,
  permission error), the decrypted plaintext is stranded at `output.tmp.<hex>` with no
  mention of that path in the error message. Include `temp_path` in the error, or only
  disarm after a successful rename.

- **`src/main.rs:292` — `parse_public_composite_key` accepts kem_len 1–8000; ML-KEM-1024 requires exactly 1568**
  A malformed key file with the wrong kem_len passes validation and fails deep inside
  encapsulation with an opaque error. Add an exact-size check:
  `if kem_len != 1568 { bail!("ML-KEM-1024 public key must be 1568 bytes") }`.

- **`src/main.rs:185` — `.unwrap()` on `String::from_utf8` in `pem_encode`**
  Safe today since base64 is always ASCII, but an undocumented panic path in production
  code. Use `String::from_utf8_unchecked` with a `// SAFETY:` comment, or slice the base64
  output as `&str` directly.

- **`tests/helpers/temp_files.rs:37` — Expect scripts interpolate paths and passwords without Tcl escaping**
  If any value contains `[`, `]`, `{`, `}`, `"`, `\`, or `$`, the generated Tcl script will
  malfunction or inject commands. The current `TEST_PASSWORD` is safe, but this is a fragile
  constraint on future tests. Escape interpolated values for Tcl, or replace `expect` with a
  Rust-native pseudo-terminal crate.
