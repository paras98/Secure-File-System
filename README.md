
# Secure File Storage System 🛡️

## Overview

This project implements a secure file storage system named `stor`, designed to store files securely and ensure data privacy and integrity. `stor` facilitates appending new information to an encrypted database and retrieves content based on specific queries and keys, employing an authentication token for user verification. Developed with a focus on security, this system underwent rigorous testing and enhancements through attacking and fixing vulnerabilities in a simulated competitive environment.

## Features 🌟

- **Secure User Authentication** 🔑: Utilizes an authentication token supplied via command-line arguments for user verification.
- **Encrypted File Storage** 📁: Stores all user files in a secure, isolated database (`enc.db`), ensuring data privacy and integrity.
- **Efficient Data Manipulation** 🛠️: Supports registering users with their keys, and reading/writing files based on user-specific keys.
- **Adherence to Security Protocols** 📜: Incorporates a `win()` function for simulation purposes, and employs `dlmalloc` for memory management to maintain a balance between efficiency and security.

## Implementation Details 🔍

### Core Functionalities

- **User Registration and Authentication** 🗝️: Utilizes SHA-256 for hashing user keys, ensuring secure authentication. A unique nonce is generated for each user session to prevent replay attacks.
- **Secure File Storage** 🏦: Implements libsodium's authenticated encryption to store files in an encrypted database (`enc.db`), providing confidentiality, integrity, and authenticity.
- **File Management** 🗂️: Supports operations such as file creation, reading, and writing, ensuring that only authorized users can access their files.

### Data Structures

- **Linked Lists for Users and Files** 🔗: Utilizes dynamic data structures to manage users and their files efficiently, facilitating quick searches and updates.
- **Nonce Management** ⏱️: Employs nonces in conjunction with user keys for encryption, enhancing security by mitigating certain cryptographic attacks.

### Encryption

- **libsodium for Cryptography** 🔐: Adopts libsodium for its robust, high-security cryptographic primitives. This choice ensures strong encryption and decryption capabilities, leveraging industry-standard practices.
- **SHA-256 for Hashing** 🧂: Uses SHA-256 hashing for user keys, providing a secure way to authenticate users without storing their actual keys.

### Security Measures

- **Input Sanitization** 🧼: Incorporates URL encoding and decoding functions to sanitize input, preventing injection attacks.
- **Error Handling** 🚫: Implements comprehensive error handling to prevent leaks of sensitive information through error messages or misbehaviors.

## Security Model 🛡️

`stor`'s security model is built around the principle of least privilege and confidentiality:

- **Authentication Tokens** 🔏: Requires tokens for user actions, ensuring that each operation is performed by an authenticated user.
- **Encrypted Storage** 🏆: Files are stored in an encrypted format within `enc.db`, making unauthorized access or modifications infeasible for attackers without the correct nonce and key.
- **Replay Attack Mitigation** 🔄: Utilizes nonces to protect against replay attacks, where an attacker might try to re-submit a previously captured request.

## Getting Started 🚀

### Prerequisites

- GCC compiler 🖥️
- Make 🛠️
- libsodium library 📚

### Setup

1. Clone the repository:
```
   bash
   git clone <repository-url>
```

### Running 'stor' 
`./stor -u <username> -k <secretkey> [action] [options]`
**Creating New File 🆕:**
`./stor -u alice -f diary.txt create`
**Writing to a File ✍️:**
`./stor -u alice -f diary.txt -k secretKey123 write "Dear diary,"`
**Read a file 📖:**
`./stor -u alice -f diary.txt -k secretKey123 read`
