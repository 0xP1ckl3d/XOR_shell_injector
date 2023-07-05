# Rust Shellcode Loader

A Rust-based shellcode loader that is designed to execute encrypted shellcode. It uses the Windows API to allocate memory, create a new thread, and execute the shellcode in the context of that thread. The shellcode is encrypted with a simple XOR cipher for basic obfuscation.

## Components

### Python Script (generate_shellcode.py)

This script uses Metasploit's msfvenom tool to generate a reverse shell payload, which is a type of shellcode that opens a connection from the target system back to an attacker-controlled system. The payload is configured to connect back to the IP address and port number specified by the user. The payload is then XOR-encoded with a random key to help evade detection by antivirus software. The XOR-encoded payload is printed out in a format that can be used in the Rust application.

### Rust Application (main.rs)

This application takes the XOR-encoded payload from the Python script and injects it into its own process memory. It then creates a new thread to execute the payload. The application waits for the thread to finish execution before it exits.

## Features

- **Shellcode Generation and Encoding**: The Python script generates a reverse shell payload that can be used to gain remote control of a system. The payload is XOR-encoded to help evade detection by antivirus software.
- **Shellcode Injection and Execution**: The Rust application injects the XOR-encoded payload into its own process memory and then executes it in a new thread. This results in the creation of a reverse shell, which opens a connection from the target system back to the attacker-controlled system.
- **Stealth**: The Rust application is compiled with the --subsystem,windows linker flag, which means it doesn't create a console window when it runs. This makes the execution of the payload more stealthy.


## Dependencies

The project depends on the `winapi` crate, which provides raw FFI bindings to Windows APIs.

## Installing Dependencies in Kali

To install the necessary dependencies in Kali Linux, you need to install Rust and the Rust package manager, Cargo. You can do this by running the following commands:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Next, you need to add the x86_64-pc-windows-gnu target to allow cross-compiling to Windows from Kali:

```bash
rustup target add x86_64-pc-windows-gnu
```

To install Metasploit on Kali Linux by running 

```bash
sudo apt-get install metasploit-framework`.
```

## Customizing the Program

There are several aspects of the program that you can customize:

* __Shell Type:__ The shell type is determined by the shellcode you provide. You can use any shellcode that is compatible with the target system.
* __Shellcode:__ You can replace the __ENCRYPTED_SHELLCODE__ constant in __main.rs__ with your own shellcode. The shellcode should be a byte array. Ensure to also change the __LENGTH__ to match the output from __generate_shellcode.py__.
* __XOR Key:__ You can replace the __XOR_KEY__ constant in main.rs with your own XOR key. The key should be a single byte.

## Usage

1. Generate the shellcode using the Python script:
```bash
python3 generate_shellcode.py <IP> <Port>
```
2. Copy the generated shellcode, length and XOR key.
3. Replace the `SHELLCODE`, `LENGTH` and `XOR_KEY` constants in `main.rs` with the copied values

##Compiling
From the home folder run:

```bash
cargo build --target x86_64-pc-windows-gnu --release
```
This will create a release build of the program, targeting Windows.

## Generator Script

The generator script is a Python script that generates the encrypted shellcode and XOR key. It takes raw shellcode as input, generates a random XOR key, encrypts the shellcode with the XOR key, and then outputs the encrypted shellcode and XOR key in a format that can be directly copied into __main.rs__.
