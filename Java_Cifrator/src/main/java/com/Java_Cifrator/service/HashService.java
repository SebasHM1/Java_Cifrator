package com.Java_Cifrator.service;
import com.Java_Cifrator.core.CryptoConstants;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashService {
    public byte[] calculateSHA256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(CryptoConstants.HASH_ALGORITHM);
        return digest.digest(data);
    }

    public String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}