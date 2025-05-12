package com.Java_Cifrator.service;

import com.Java_Cifrator.core.CryptoConstants;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class KeyService {
    public SecretKey generateKey(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(CryptoConstants.PBKDF2_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, CryptoConstants.ITERATION_COUNT, CryptoConstants.KEY_LENGTH_BITS);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    public byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[CryptoConstants.SALT_LENGTH_BYTES];
        random.nextBytes(salt);
        return salt;
    }

    public byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[CryptoConstants.IV_LENGTH_BYTES];
        random.nextBytes(iv);
        return iv;
    }
}