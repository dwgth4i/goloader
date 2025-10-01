import os
import argparse
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
KEY_SIZE = 32  # 256 bits for AES-256
NONCE_SIZE = 12 # 96 bits recommended for GCM
TAG_SIZE = 16  # 128 bits authentication tag

def generate_key():
    """Generates a secure, random 256-bit key."""
    return os.urandom(KEY_SIZE)

def encrypt_file(input_filepath, output_filepath, key):
    """
    Encrypts a file using AES-256-GCM.

    The output is raw binary data in the Go-compatible format:
    Nonce (12 bytes) + Ciphertext + Tag (16 bytes).
    """
    try:
        with open(input_filepath, 'rb') as f:
            plaintext = f.read()
    except FileNotFoundError:
        print(f"[-] Error: Input file not found at {input_filepath}")
        return False

    # Generate a unique nonce (Initialization Vector)
    nonce = os.urandom(NONCE_SIZE)

    # Initialize the cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the data
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # The GCM mode produces an authentication tag upon finalization
    tag = encryptor.tag

    # The output data bundle (raw binary)
    output_data_bytes = nonce + ciphertext + tag

    # Write as raw binary
    try:
        with open(output_filepath, 'wb') as f:
            f.write(output_data_bytes)
        print(f"[+] Encryption successful! Output is raw binary.")
        print(f"[+] Encrypted file saved to: {output_filepath}")
        return True
    except IOError as e:
        print(f"[-] Error writing raw binary output file: {e}")
        return False

# --- Main Logic ---

if __name__ == "__main__":

    # Check for the required library
    try:
        import cryptography
    except ImportError:
        print("!!! WARNING: The 'cryptography' library is not installed. !!!")
        print("Please install it using: pip install cryptography")
        exit(1)

    parser = argparse.ArgumentParser(
        description="AES-256-GCM encryption utility (32-byte random key generation).",
    )
    parser.add_argument('input', help="Path to the file to be encrypted.")
    parser.add_argument('-o', '--output', help="Output file path (defaults to input.enc).", default='')
    parser.add_argument('-k', '--keyfile', help="Write Base64 key to this file (UTF-16LE). If omitted, defaults to <input>.key", default='')
    args = parser.parse_args()

    # --- Key Generation ---
    encryption_key = generate_key()

    # Standard Base64 (with padding)
    b64_key = base64.b64encode(encryption_key).decode('ascii')

    print("\n[--- ENCRYPTION KEY (32-byte raw key in BASE64) ---]")
    print(b64_key)
    print("-------------------------------------------------------------------\n")

    # --- Output Path Setup ---
    if not args.output:
        args.output = args.input + '.enc'
    if not args.keyfile:
        args.keyfile = args.input + '.key'

    # --- Encryption ---
    ok = encrypt_file(args.input, args.output, encryption_key)
    if not ok:
        exit(1)

    # --- Write key file in UTF-16LE ---
    # We write the ASCII base64 string encoded as UTF-16LE bytes (no BOM).
    try:
        with open(args.keyfile, 'wb') as kf:
            kf.write(b64_key.encode('utf-16le'))
        print(f"[+] Key file written (UTF-16LE) -> {args.keyfile}")
    except IOError as e:
        print(f"[-] Error writing key file {args.keyfile}: {e}")
        exit(1)

