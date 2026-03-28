package wow.kleidaria;

//AES-GCM encryption
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//Argon2
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

// Ed25519
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;

// RNG and String Manipulation
import java.security.SecureRandom;
import java.util.Base64;

// Lombok
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CryptoUtil {

    private static final SecureRandom RNG = new SecureRandom();
    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;

    // --- Instance config ---
    private int argon2Iterations;
    private int argon2Memory;
    private int argon2Parallelism;

    private int masterSaltBytes;
    private int nonceBytes;
    private int encryptionSaltBytes;
    private int encryptionKeyBytes;
    private int IdBytes;

    public void resetConfig() {
        this.argon2Iterations = 1000_000;
        this.argon2Memory = 65536;
        this.argon2Parallelism = 4;

        this.masterSaltBytes = 32;

        this.encryptionSaltBytes = 16;
        this.encryptionKeyBytes = 32;

        this.nonceBytes = 12;

        this.IdBytes = 16;
    }

    public CryptoUtil() {
        resetConfig();
    }

    // -------------------------------------------------------------------------
    // Key generation / derivation
    // -------------------------------------------------------------------------

    public byte[] generateMasterSalt() {
        return randomBytes(masterSaltBytes);
    }

    public byte[] generateNonce() {
        return randomBytes(nonceBytes);
    }

    public byte[] generateEncryptionKey() {
        return randomBytes(encryptionKeyBytes);
    }

    public byte[] generateEncryptionSalt() {
        return randomBytes(encryptionSaltBytes);
    }

    public String generateID() {
        return toBase64Url(randomBytes(IdBytes));
    }

    public byte[] deriveMasterKey(char[] password, byte[] salt) {
        try {
            Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(argon2Iterations)
                    .withMemoryAsKB(argon2Memory)
                    .withParallelism(argon2Parallelism)
                    .withSalt(salt)
                    .build();

            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(params);

            byte[] derived = new byte[encryptionKeyBytes];
            generator.generateBytes(password, derived);
            return derived;
        } catch (Exception e) {
            throw new RuntimeException("Argon2 key derivation failed", e);
        }
    }

    public HashMap<String, byte[]> generateEd25519KeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            KeyPair kp = kpg.generateKeyPair();

            HashMap<String, byte[]> keys = new HashMap<>();
            keys.put("publicKey", kp.getPublic().getEncoded());
            keys.put("privateKey", kp.getPrivate().getEncoded());
            return keys;
        } catch (Exception e) {
            throw new RuntimeException("Ed25519 key generation failed", e);
        }
    }

    public byte[] encryptEd25519(byte[] encodedPrivateKey, byte[] message) {
        try {
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));

            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(message);
            return sig.sign();
        } catch (Exception e) {
            throw new RuntimeException("Ed25519 signing failed", e);
        }
    }

    public byte[] encryptEd25519(String base64PrivateKey, byte[] message) {
        return encryptEd25519(fromBase64Url(base64PrivateKey), message);
    }

    public boolean decryptEd25519(byte[] encodedPublicKey, byte[] message, byte[] signature) {
        try {
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(encodedPublicKey));

            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(publicKey);
            sig.update(message);
            return sig.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException("Ed25519 verification failed", e);
        }
    }

    public boolean decryptEd25519(String base64PublicKey, byte[] message, byte[] signature) {
        return decryptEd25519(fromBase64Url(base64PublicKey), message, signature);
    }

    // -------------------------------------------------------------------------
    // AES-GCM encrypt / decrypt
    // -------------------------------------------------------------------------

    public byte[] encrypt(byte[] keyBytes, byte[] nonce, byte[] plain) {
        SecretKeySpec key = new SecretKeySpec(keyBytes, AES_ALGORITHM);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            return cipher.doFinal(plain);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM encryption failed", e);
        } finally {
            tryDestroy(key);
        }
    }

    public byte[] decrypt(byte[] keyBytes, byte[] nonce, byte[] cipherText) {
        SecretKeySpec key = new SecretKeySpec(keyBytes, AES_ALGORITHM);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            return cipher.doFinal(cipherText);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM decryption failed", e);
        } finally {
            tryDestroy(key);
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static byte[] randomBytes(int length) {
        byte[] b = new byte[length];
        RNG.nextBytes(b);
        return b;
    }

    private static void tryDestroy(SecretKeySpec key) {
        try {
            key.destroy();
        } catch (Exception ignored) {
        }
    }

    public static String toBase64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static byte[] fromBase64Url(String base64) {
        return Base64.getUrlDecoder().decode(base64);
    }
}