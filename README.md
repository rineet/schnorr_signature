## Schnorr Signature Utilities (Python)

This project implements Schnorr digital signatures over the secp256k1 curve and exposes simple command‑line tools for key generation, signing, and verification.

### Features
- **Elliptic‑curve primitives**: Custom implementation of point addition, scalar multiplication, and key/point conversions on secp256k1 (`schnorr_lib.py`, `schnorr_lib1.py`, `schnorr_lib2.py`).
- **Schnorr signatures**: BIP‑340–style signing and verification for 32‑byte message digests.
- **Key management**: Random private key generation and corresponding public keys stored in `users.json` (`create_key.py`).
- **CLI tools**:
  - **Sign**: `python schnorr_signature/schnorr_sign.py -m "your message"`
  - **Verify**: `python schnorr_signature/schnorr_verify.py -m "your message" -p <public_key_hex> -s <signature_hex>`
- **Performance instrumentation**: Alternative libraries measure timing of point addition/multiplication and log or print detailed performance statistics.

### Project Structure
- `schnorr_signature/schnorr_lib.py` – Core Schnorr implementation (sign/verify and curve math).
- `schnorr_signature/schnorr_lib1.py`, `schnorr_signature/schnorr_lib2.py` – Variants with detailed timing and logging for performance analysis.
- `schnorr_signature/create_key.py` – Generates keypairs and stores them in `users.json`.
- `schnorr_signature/schnorr_sign.py` – CLI for signing messages using a stored private key.
- `schnorr_signature/schnorr_verify.py` – CLI for verifying signatures given message, public key, and signature.
- `schnorr_signature/users.json` – Example key storage file.

### Usage
1. **Create a keypair**
   ```bash
   python schnorr_signature/create_key.py
   ```
2. **Sign a message**
   ```bash
   python schnorr_signature/schnorr_sign.py -m "hello world"
   ```
3. **Verify a signature**
   ```bash
   python schnorr_signature/schnorr_verify.py -m "hello world" -p <public_key_hex> -s <signature_hex>
   ```

### Requirements
- **Python 3.8+**
- Standard library only (no external dependencies).


