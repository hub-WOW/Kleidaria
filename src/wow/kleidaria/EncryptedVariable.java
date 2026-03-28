package wow.kleidaria;

import java.util.Arrays;
public class EncryptedVariable {

    private final byte[] nonce;
    private final byte[] ciphertext;
    private final byte[] encryptedKey;
    private final byte[] salt;

    public EncryptedVariable(byte[] nonce, byte[] ciphertext, byte[] encryptedKey, byte[] salt) {
        this.nonce = Arrays.copyOf(nonce, nonce.length);
        this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
        this.encryptedKey = Arrays.copyOf(encryptedKey, encryptedKey.length);
        this.salt = Arrays.copyOf(salt, salt.length);
    }

    public byte[] getNonce() {
        return Arrays.copyOf(nonce, nonce.length);
    }

    public byte[] getCiphertext() {
        return Arrays.copyOf(ciphertext, ciphertext.length);
    }

    public byte[] getEncryptedKey() {
        return Arrays.copyOf(encryptedKey, encryptedKey.length);
    }

    public byte[] getSalt() {
        return Arrays.copyOf(salt, salt.length);
    }
}