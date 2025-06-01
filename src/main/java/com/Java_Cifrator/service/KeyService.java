package com.Java_Cifrator.service;

import com.Java_Cifrator.core.CryptoConstants;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Service
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

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public PublicKey getPublicKeyFromBytes(byte[] publicKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public KeyPair getKeyPairFromPrivateKeyBytes(byte[] privateKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        
        // Generate a new key pair and replace the private key
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        return new KeyPair(keyPair.getPublic(), privateKey);
    }
}