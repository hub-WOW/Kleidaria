# Kleidaria

**Kleidaria** is a lightweight cryptography utility library written in Java.  
It provides secure primitives for password-based key derivation and authenticated encryption using modern algorithms.

The name **Kleidaria** comes from the Greek word *κλειδαριά*, meaning **“lock.”**

---

## Features

- Argon2id password-based key derivation
- AES‑256‑GCM authenticated encryption
- Ed25519 asymmetric key pair generation, signing, and verification
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

### Encrypting data (AES-256-GCM)

```java
byte[] key = crypto.generateEncryptionKey();
byte[] nonce = crypto.generateNonce();

byte[] ciphertext = crypto.encrypt(
    key,
    nonce,
    "secret message".getBytes()
);
```

### Decrypting data (AES-256-GCM)

```java
byte[] plaintext = crypto.decrypt(
    key,
    nonce,
    ciphertext
);
```

---

## Ed25519 Asymmetric Cryptography

Ed25519 provides fast, secure asymmetric signing and verification. In Kleidaria the operation is exposed through `encryptEd25519` (sign) and `decryptEd25519` (verify).

The methods are overloaded to accept either raw **byte arrays** or **Base64 URL-safe strings**.

### Generating a key pair

```java
import java.util.HashMap;

HashMap<String, byte[]> keyPair = crypto.generateEd25519KeyPair();

byte[] publicKey  = keyPair.get("publicKey");
byte[] privateKey = keyPair.get("privateKey");

// Convert to strings if needed
String pubBase64  = CryptoUtil.toBase64Url(publicKey);
String privBase64 = CryptoUtil.toBase64Url(privateKey);
```

### Signing a message (`encryptEd25519`)

You can sign using either the `byte[]` or the `String` formatted private key:

```java
byte[] message = "hello world".getBytes();

// Option A: Raw bytes
byte[] sig1 = crypto.encryptEd25519(privateKey, message);

// Option B: Base64 URL string
byte[] sig2 = crypto.encryptEd25519(privBase64, message);
```

### Verifying a signature (`decryptEd25519`)

Similarly, verification supports both formats:

```java
// Option A: Raw bytes
boolean ok1 = crypto.decryptEd25519(publicKey, message, sig1);

// Option B: Base64 URL string
boolean ok2 = crypto.decryptEd25519(pubBase64, message, sig2);
```

### Full round-trip example

```java
CryptoUtil crypto = new CryptoUtil();

// 1. Generate
HashMap<String, byte[]> kp = crypto.generateEd25519KeyPair();
String privStr = CryptoUtil.toBase64Url(kp.get("privateKey"));
String pubStr  = CryptoUtil.toBase64Url(kp.get("publicKey"));

// 2. Sign (using string)
byte[] msg = "kleidaria".getBytes();
byte[] sig = crypto.encryptEd25519(privStr, msg);

// 3. Verify (using string)
boolean ok = crypto.decryptEd25519(pubStr, msg, sig);
System.out.println("Valid: " + ok); // true
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