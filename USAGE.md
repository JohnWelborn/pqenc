# Usage Guide

The intended workflow for pqenc: generate a keypair once, verify you can
restore before relying on it, then encrypt regularly and decrypt only when
needed.

## 1. Generate a keypair (once, on a secure machine)

```bash
pqenc generate-keys --public-key pub.key --private-key priv.key
```

Store `priv.key` somewhere secure and offline. Copy `pub.key` to the machine that will be doing backups.

Key generation prints a fingerprint and randomart image for the new keypair,
in the style of `ssh-keygen`. Note it down (or compare it by eye against the
randomart) so you can later confirm the `pub.key` on the backup machine still
matches this `priv.key` — see the next two sections.

**The passphrase cannot be recovered.** `priv.key` is stored encrypted, and the
passphrase is the only thing that opens it. There is no recovery path, no escrow,
and no way to strip encryption from an already-encrypted key without the
passphrase — none of pqenc's commands can help you here. Losing the passphrase
destroys your backups just as completely as losing `priv.key` itself; neither
half is any use without the other.

This is a deliberate design choice, and it means the passphrase should be stored
**with** the offline private key rather than treated as an independent secret.
The two defend against different threats — the encrypted file protects against
someone who obtains your backups, the passphrase protects against someone who
obtains the file — and neither threat is the one pqenc is built around. An
attacker who compromises the backup machine gets only `pub.key` either way.

If you deliberately want no passphrase — e.g. the key already lives on an
encrypted volume, or this is a throwaway test key — pass an empty one:
`--passphrase ""`. This stores `priv.key` in **plain text**; anyone who can
read that file can decrypt everything encrypted to the matching public key, no
passphrase required. Only do this if the file's own storage is the sole
protection you're relying on.

## 2. Verify you can restore (once, before relying on any backup)

Do a full round trip with the keys you just generated:

```bash
echo "restore test" > test.txt
pqenc encrypt --public-key pub.key test.txt --output test.pqe
pqenc decrypt --private-key priv.key test.pqe --output test.out
cmp test.txt test.out && echo "restore verified"
```

Nothing in the file format ties an encrypted file to a particular key, so
encrypting to the wrong public key succeeds and reports success every time.
(The embedded original filename, used to default `--output` on decrypt, is
authenticated against tampering in transit, but not against a dishonest
sender — anyone holding your public key can embed any filename they like.
`pqenc decrypt` sanitizes it before ever using it as a path, but don't treat
the restored name as attacker-independent information.)
This restore drill is the most thorough check, but not the only one:
`pqenc encrypt` also prints the recipient key's fingerprint on every run, and
`pqenc fingerprint pub.key` / `pqenc fingerprint priv.key` print it on
demand for either half of a keypair. Run it on both
machines after distributing a key and compare the `SHA256:...` line (or the
randomart) by eye — a mismatch here means `pub.key` and `priv.key` do not
belong together, likely because keys were regenerated and only one file was
copied, or the wrong file was grabbed. Without one of these checks, a mismatch
surfaces only when you try to restore, which may be months later. Repeat
whichever check you use whenever you replace or move either key file.

## 3. Encrypt backups (regularly, on the backup machine)

```bash
# Encrypt a single file
pqenc encrypt --public-key pub.key data.tar.gz --output data.tar.gz.pqe

# Encrypt a directory without writing plaintext to disk
tar czf - /path/to/data | pqenc encrypt --public-key pub.key - --output backup.tar.gz.pqe
```

Encrypted output is written with mode `0600` (owner read/write only). If a backup
agent running as a different user needs to read it, adjust permissions or ownership
after encryption.

Encryption refuses to overwrite an existing output file. Output is claimed by
creating a small placeholder file at the destination path before any encryption
work begins -- this claim is also what makes the "refuses to overwrite" check
atomic and race-free -- and the real ciphertext is streamed to a sibling
temporary file and renamed into place only on success. An ordinary failure
removes the placeholder immediately, so a normal retry to the same path just
works. A hard kill (e.g. `SIGKILL`) or power loss can't run that cleanup and
may leave the placeholder behind, but pqenc recognizes its own placeholders
and safely reclaims them on the next attempt to the same path, so retries are
not permanently blocked.

`pqenc encrypt` always writes the current file format, `PQE4`: plaintext is
divided into fixed 8 GiB segments, each encrypted under its own independently
HKDF-derived AES-256-GCM key, so no single key ever encrypts more than 8 GiB
even for very large backups. `pqenc decrypt` and `pqenc verify` also accept
the older `PQE3` format, so files encrypted by a pre-PQE4 `pqenc` release
keep working without needing that older release.

## 4. Check backup integrity without the private key (optional, cron-friendly)

```bash
pqenc verify backup.tar.gz.pqe
```

Checks magic bytes and header structure, and — for files carrying a checksum
trailer (every file `pqenc encrypt` produces) — recomputes and compares a
SHA-256 over the whole file. Needs no private key or passphrase, so it's safe
to run unattended, e.g. right after each backup in the same cron job that ran
`pqenc encrypt`. Exits `0` if valid, non-zero otherwise.

This is a plain checksum, not authentication: it catches accidental
corruption (bit rot, truncation, a bad copy), not deliberate tampering —
anyone with write access to the file can recompute it after modifying the
file. `pqenc decrypt`'s AEAD tags are what actually protect against
tampering, at restore time, when the private key is available.

The checksum trailer is mandatory; a file missing it is rejected outright,
not silently tolerated.

`pqenc decrypt` also runs this same check itself, automatically, before
touching the private key — see the next step.

## 5. Decrypt to restore (only when needed, using the private key)

```bash
pqenc decrypt --private-key priv.key backup.tar.gz.pqe --output backup.tar.gz
```

Decrypt always verifies the file first (the same check as `pqenc verify`,
run automatically) and aborts with a clear error before touching the private
key or writing any output if that fails — so a corrupted file is rejected up
front rather than partway through decryption.

`--output` can be omitted: decrypt then restores the original filename (and
modification/access times) embedded in the encrypted file, falling back to
stripping a trailing `.pqe` from the input path if no filename was embedded
(e.g. one encrypted from stdin).

If preferred, decryption can be performed on an offline or air-gapped machine by transferring the encrypted file there.
