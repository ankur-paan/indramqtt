# Licence signing ceremony (B2-03)

How the root licence-signing keys are created, stored, used and retired.
Read this before touching a signing device or a trusted-keys file. The
short version: the private keys live on hardware tokens and never leave
them; the broker only ever sees public keys; rotation is a configuration
change, never a rebuild.

## Algorithm and device choice

- Signatures are **ECDSA P-256 with SHA-256**. Verification uses the
  `p256` crate (Apache-2.0 OR MIT); no curve arithmetic is hand-rolled.
- This is decided by the hardware, not by taste: our devices report
  **firmware 5.1.2**, and PIV Ed25519 needs firmware 5.7 or later. P-256
  is what the token in front of us can do, so P-256 is what we sign with.
- Tokens enforce **PIN plus physical touch** for every signature. A
  signature without someone present must be impossible, not just unlikely.

## Rotation is a requirement, not a nicety

Firmware below 5.7 is affected by a side-channel (EUCLEAK,
CVE-2024-45677) that can allow extraction of an ECDSA private key given
physical possession and specialist equipment. Token firmware cannot be
upgraded in the field. The practical risk to a key held securely is low,
but the design assumes every key will eventually rotate:

- The broker trusts a **set of public keys keyed by key id**, not one key.
- The licence carries the key id it was signed with; verification selects
  by that id and fails closed on an unknown one.
- Retiring a key **never invalidates licences already issued**: the
  retired public key stays in the trusted set until the last licence it
  signed expires, then it is removed.
- Moving to a newer device later is a **configuration change, not a
  rebuild**: enrol the new public key, sign with the new device, retire
  the old key on its own schedule. Outstanding licences keep verifying
  throughout because both public keys are trusted during the overlap.

## Roles

- **Custodian** holds the tokens and the sealed backup, runs the signing
  tool, and types YES. There should be two custodians who can each do
  this alone; a ceremony that needs a specific person in the room will
  fail the week they are away.
- **Operator** maintains the trusted-keys file on the brokers and
  restarts nodes to pick up key changes. The operator never sees private
  key material: there is nothing to see.

## 1. Generating the key on the device

Generate on the token so the private key is born non-importable and
non-exportable. There is deliberately no `genkey` in the signing tool:
a command that writes a private key to a file teaches the wrong habit.

Example with the vendor PIV tool (slot 9c is the signature slot; the
exact flags for the current tool version are in the tool manual):

1. Reset the PIV application on a fresh device, then set a PIN and PUK
   from the password manager. Record that the defaults were changed;
   do not record the values anywhere else.
2. Set the touch policy for slot 9c to **cached** or **always**: every
   signature must require a touch.
3. Generate the P-256 keypair **on the device** in slot 9c with
   attestation. Export the public key (SEC1) and the attestation
   certificate; the private key cannot be exported, and that is the point.
4. Assign the key id now, before anything is signed: `yk-piv-01` for the
   first device, `yk-piv-02` for the second. The id goes into every
   licence (`kid`) and into the broker trust file. Key ids are never
   reused, even after retirement.

## 2. Enrolling two devices

Enrol **two devices with different key material** from day one, so one
lost or broken token is an incident, not an outage:

1. Repeat section 1 on a second device. It must generate its own key;
   cloning a key between devices defeats the purpose.
2. Add both public keys to the broker trusted-keys file (JSON,
   `{"keys": [{"kid": "...", "public_key_hex": "<SEC1 hex>"}]}`),
   or one file per key in a directory passed as `--license-keys`.
3. Restart one broker node and check the boot log names both key ids.
   Roll the file to the remaining nodes only after the first node shows
   both ids.
4. Issue the first real licence with `yk-piv-01`. Keep `yk-piv-02`
   enrolled and tested (sign one throwaway licence against a scratch
   request, verify it on a scratch node, then discard the throwaway) so
   the second path is known to work before it is needed.

## 3. Where the backup is sealed

- The **backup is a third device**, generated and enrolled exactly like
  the first two (key id `yk-piv-03`), then sealed in a tamper-evident bag
  and stored off-site (safe deposit or equivalent). It is a device, not
  a file: there is deliberately no exportable copy of any private key.
- The sealed envelope holds: the device, the key id, the date, and the
  PIN/PUK in a separate sealed inner envelope. Access is logged in the
  licence register (section 6).
- The trusted-keys file on the brokers does **not** need to list the
  backup key until it is unsealed. Enrol it at unseal time following
  section 5; until then it signs nothing and the brokers trust nothing
  extra.
- If the backup is ever unsealed, that is a rotation event: order a
  replacement device, enrol it, and re-seal.

## 4. Issuing a licence

1. Receive the request file from the customer installation. It carries
   the installation identity; confirm with `license-signer show-request`.
2. Run `license-signer sign --request <file> --kid <id> --customer ...
   --max-nodes ... --issued-at ... --expires-at ...`. The tool copies the
   identity from the request into the payload and refuses an empty one
   rather than inventing an identity.
3. The tool prints customer, identity, entitlements, expiry, key id and
   the SHA-256 digest of the canonical payload, then waits for `YES`.
   Read the screen, compare the digest with the ceremony record, touch
   the token when it blinks. Nothing touches the token before YES.
4. Send the printed `INDRA-ENT-V2.<payload>.<signature>` token to the
   customer. Record digest, key id, customer and expiry in the register.
5. The canonical bytes are `serde_json::to_vec` of the payload struct in
   field order (customer, max_nodes, issued_at, expires_at, features,
   node_id, kid). The same licence always hashes the same bytes, and the
   signature covers all of it.

## 5. Retiring a key

1. Stop signing with the old key id immediately. New licences use the
   successor id.
2. **Leave the retired public key in the trusted-keys file** until the
   latest `expires_at` among licences it signed has passed, plus a margin
   of one release cycle. Query the register for that date; do not guess.
3. Only then remove its entry, roll the file, and confirm each node logs
   the smaller set at boot. A licence signed by the retired key verifies
   until its own expiry throughout this window; nothing is reissued.
4. Mark the retired device (labels, register) so it is never re-enrolled
   under a new id with old material. Wipe or destroy it per policy.

## 6. Adopting a newer device without reissuing

This is the normal upgrade path (for example moving to firmware that
supports Ed25519, or replacing a token after EUCLEAK handling):

1. Generate and enrol the new device key under a fresh key id alongside
   the current ones (section 1). The brokers now trust old and new.
2. Switch issuance to the new key id. Old licences keep verifying
   because the old public key is still trusted.
3. Retire the old key on the schedule in section 5. No outstanding
   licence is reissued at any step.

## 7. Licence register

Keep a small append-only record (paper or versioned file, separate from
this repository): date, customer, installation identity, key id, digest,
expiry, custodian initials. It answers "which key signed this?" and "when
can we drop this public key?" without decoding tokens under pressure.

## What was exercised for B2-03

Verification and the software round trip are covered by automated tests
in `crates/broker-cluster` (two enrolled P-256 keys, forged and
relabeled tokens, unknown key id, expiry, node binding, trust-file
loading, and the SWIM join path). The signing tool was exercised with
its `--signer software` stand-in. The hardware path (`--signer token`
through the digest helper, PIN plus touch on the device) is implemented
but **not tested against a real device** in this task; the first real
issuance must follow sections 1-4 above and record the device serial in
the register.
