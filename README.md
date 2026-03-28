# Kleidaria

**Kleidaria** is a lightweight cryptography utility library written in Java.  
It provides secure primitives for password-based key derivation and authenticated encryption using modern algorithms.

The name **Kleidaria** comes from the Greek word *κλειδαριά*, meaning **“lock.”**

---

## Features

- Argon2id password-based key derivation
- AES‑256‑GCM authenticated encryption
- Secure random key and nonce generation
- Base64 URL-safe encoding helpers
- Simple object-oriented API
- Configurable cryptographic parameters

---

## Example Usage

### Creating the utility

```java
CryptoUtil crypto = new CryptoUtil();
```

### Deriving a master key from a password

```java
byte[] salt = crypto.generateMasterSalt();

byte[] masterKey = crypto.deriveMasterKey(
    "password".toCharArray(),
    salt
);
```

### Encrypting data

```java
byte[] key = crypto.generateEncryptionKey();
byte[] nonce = crypto.generateNonce();

byte[] ciphertext = crypto.encrypt(
    key,
    nonce,
    "secret message".getBytes()
);
```

### Decrypting data

```java
byte[] plaintext = crypto.decrypt(
    key,
    nonce,
    ciphertext
);
```

---

## Configuration

Kleidaria allows tuning of important cryptographic parameters.

Example:

```java
CryptoUtil crypto = new CryptoUtil();

crypto.setArgon2Iterations(1_000_000);
crypto.setArgon2Memory(65536);
crypto.setArgon2Parallelism(4);
```

These parameters control the security cost of password derivation.

---

## Generated Values

The library can generate secure values for common tasks:

- Unique IDs
- Nonces
- Encryption keys
- Salts

Example:

```java
String id = crypto.generateID();
```

---

## EncryptedVariable

The `EncryptedVariable` class is a small immutable container used to store encrypted values together with the metadata required for decryption:

- nonce
- ciphertext
- encrypted key
- salt

All byte arrays are defensively copied to prevent external mutation.

---

## Notes

- Nonces must **never be reused with the same key**.
- Argon2 parameters should be tuned based on the hardware where the application runs.

---