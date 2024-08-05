#pyC4.py shellcode.bin --key "TESTKEY"

import sys
import argparse

def rc4(key, data):
    S = list(range(256))
    j = 0
    out = []

    # KSA Phase
    key = [ord(c) for c in key]
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA Phase
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    return bytes(out)

def main():
    parser = argparse.ArgumentParser(description='Perform RC4 encryption on a binary file.')
    parser.add_argument('input_file', help='The input binary file to encrypt.')
    parser.add_argument('--key', required=True, help='The encryption key.')

    args = parser.parse_args()

    try:
        with open(args.input_file, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.input_file}' not found.")
        sys.exit(1)

    encrypted_data = rc4(args.key, data)

    output_file = args.input_file.replace('.bin', '') + '_encrypted.bin'
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

    print(f"Encryption complete. Encrypted data written to '{output_file}'.")

    # Print the encrypted shellcode and key in the specified format
    print("unsigned char uPayload[] = {")
    for i, byte in enumerate(encrypted_data):
        if i % 16 == 0:
            print()
        print(f"0x{byte:02X}, ", end='')
    print("\n};")

    print("\nunsigned char Rc4Key[] = {")
    for i, byte in enumerate(args.key.encode()):
        if i % 16 == 0:
            print()
        print(f"0x{byte:02X}, ", end='')
    print("\n};")

if __name__ == "__main__":
    main()
