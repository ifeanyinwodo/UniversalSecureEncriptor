
# UniversalSecureEncriptor

UniversalSecureEncriptor is a robust C# library for secure encryption and decryption of files and text using modern cryptographic standards. It is designed to be easy to use, highly secure, and suitable for a wide range of applications.

## Project Information

- **Project Name:** UniversalSecureEncriptor
- **Author:** Ifeanyi Nwodo
- **License:** Apache-2.0

---

## Features

- **AES-GCM Encryption:** Uses AES-GCM for authenticated encryption, ensuring both confidentiality and integrity.
- **Password-Based Key Derivation:** Keys are derived securely from user passwords using PBKDF2 (SHA-256).
- **File & Text Support:** Encrypt and decrypt both files and text strings.
- **Base64 & Binary Output:** Supports output as Base64 strings or raw bytes.
- **Hashing Utility:** Compute SHA-256 hashes for data integrity checks.
- **Simple API:** High-level static methods for easy integration.

---

## How It Works

### Encryption Process

1. **Key Derivation:** A cryptographic key is derived from the password and a random salt using PBKDF2.
2. **AES-GCM Encryption:** Data is encrypted using AES-GCM with a random nonce and authentication tag.
3. **Output Format:** The salt, nonce, tag, and ciphertext are combined and returned as either a Base64 string or byte array.

### Decryption Process

1. **Extract Parameters:** Salt, nonce, tag, and ciphertext are extracted from the encrypted data.
2. **Key Derivation:** The key is re-derived from the password and salt.
3. **AES-GCM Decryption:** Data is decrypted and integrity is verified using the authentication tag.

---

## API Overview

### Main Class: `SecureEncryptor`

#### Text Encryption

```csharp
string encrypted = SecureEncryptor.EncryptText("Hello World", "password123");
string decrypted = SecureEncryptor.DecryptText(encrypted, "password123");
```

#### File Encryption

```csharp
string base64 = SecureEncryptor.EncryptFileToBase64("input.txt", "password123");
byte[] bytes = SecureEncryptor.EncryptFileToBytes("input.txt", "password123");
```

#### File Decryption

```csharp
SecureEncryptor.DecryptFromBase64ToFile(base64, "output.txt", "password123");
byte[] decryptedBytes = SecureEncryptor.DecryptFromBytes(bytes, "password123");
```

#### Utility Methods

- `EncryptToBase64ToFile(inputFile, password)`
- `EncryptToBytesToFile(inputFile, password)`
- `DecryptFromBase64FileToFile(inputFile, outputFile, password)`
- `DecryptFromBytesFileToFile(inputFile, outputFile, password)`

#### Hashing

```csharp
string hash = HashUtility.ComputeSHA256(dataBytes);
```

---

## Security Details

- **AES-GCM:** Provides authenticated encryption, protecting against tampering.
- **PBKDF2 (SHA-256):** Secure key derivation with configurable iterations (default: 100,000).
- **Random Salt & Nonce:** Ensures unique encryption for each operation.
- **Authentication Tag:** Verifies data integrity during decryption.

---

## Usage Example

```csharp
// Encrypt a file and save as Base64
SecureEncryptor.EncryptToBase64ToFile("myfile.txt", "strongpassword");

// Decrypt from Base64 file to original file
SecureEncryptor.DecryptFromBase64FileToFile("myfile_encrypted.txt", "myfile_decrypted.txt", "strongpassword");

// Encrypt and decrypt text
string encrypted = SecureEncryptor.EncryptText("Secret Message", "strongpassword");
string decrypted = SecureEncryptor.DecryptText(encrypted, "strongpassword");
```

---

## Folder Structure

```
UniversalSecureEncriptor/
│
├── Helper/
│   ├── Services/
│   │   ├── FileEncryptor.cs
│   │   ├── KeyManager.cs
│   │   └── TextEncryptor.cs
│   └── Utilities/
│       └── HashUtility.cs
├── SecureEncryptor.cs
├── LICENSE
├── README.md
└── ...
```

---

## Installation


You can download and install the completed NuGet package from:

[UniversalSecureEncriptor v1.0.1 on NuGet](https://www.nuget.org/packages/UniversalSecureEncriptor/1.0.1)

Add the source files to your C# project or compile as a library. No external dependencies are required beyond .NET's standard cryptography libraries.

---

## License

This project is licensed under the [Apache-2.0 License](LICENSE).

---

## Author

**Ifeanyi Nwodo**

---

## Contributing

Contributions, issues, and feature requests are welcome! Please open an issue or submit a pull request.

---

## Disclaimer

This library is provided as-is. Always review and test cryptographic code for your specific use case and security requirements.

---


