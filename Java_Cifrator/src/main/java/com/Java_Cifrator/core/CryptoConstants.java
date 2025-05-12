package com.Java_Cifrator.core;
public final class CryptoConstants {
    private CryptoConstants() {} // Prevenir instanciación

    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String HASH_ALGORITHM = "SHA-256";
    public static final int KEY_LENGTH_BITS = 256;
    public static final int ITERATION_COUNT = 65536;
    public static final int SALT_LENGTH_BYTES = 16;
    public static final int IV_LENGTH_BYTES = 16;
}