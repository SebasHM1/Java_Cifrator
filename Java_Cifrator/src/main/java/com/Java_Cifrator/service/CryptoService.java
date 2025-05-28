package com.Java_Cifrator.service;

import com.Java_Cifrator.core.CryptoConstants;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

@Service
public class CryptoService {
    private final KeyService keyService;
    private final HashService hashService;
    private final FileHandler fileHandler;

    public CryptoService(KeyService keyService, HashService hashService, FileHandler fileHandler) {
        this.keyService = keyService;
        this.hashService = hashService;
        this.fileHandler = fileHandler;
    }

    public void encryptFile(String inputFilePath, String outputFilePath, String password) throws Exception {
        byte[] fileBytes = fileHandler.readBytes(inputFilePath);
        byte[] originalHash = hashService.calculateSHA256(fileBytes);

        byte[] salt = keyService.generateSalt();
        SecretKey secretKey = keyService.generateKey(password, salt);
        byte[] iv = keyService.generateIV();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(CryptoConstants.AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            baos.write(salt);
            baos.write(iv);
            baos.write(originalHash);
            baos.write(encryptedBytes);
            fos.write(baos.toByteArray());
        }
    }

    public void decryptFileAndVerify(String inputFilePath, String outputFilePath, String password) throws Exception {
        byte[] encryptedFileBytes = fileHandler.readBytes(inputFilePath);

        ByteArrayInputStream bis = new ByteArrayInputStream(encryptedFileBytes);
        byte[] salt = new byte[CryptoConstants.SALT_LENGTH_BYTES];
        bis.read(salt);
        byte[] iv = new byte[CryptoConstants.IV_LENGTH_BYTES];
        bis.read(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        byte[] storedHash = new byte[32];
        bis.read(storedHash);
        byte[] encryptedData = new byte[bis.available()];
        bis.read(encryptedData);
        bis.close();

        SecretKey secretKey = keyService.generateKey(password, salt);
        Cipher cipher = Cipher.getInstance(CryptoConstants.AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] decryptedBytes;
        try {
            decryptedBytes = cipher.doFinal(encryptedData);
        } catch (Exception e) {
            System.err.println("Error al descifrar: Contrasena incorrecta o archivo corrupto.");
            throw e;
        }

        fileHandler.writeBytes(outputFilePath, decryptedBytes);
        System.out.println("Archivo descifrado (maybe) en: " + outputFilePath);

        byte[] newHash = hashService.calculateSHA256(decryptedBytes);
        boolean integrityCheck = Arrays.equals(newHash, storedHash);

        if (integrityCheck) {
            System.out.println("Verificación de integridad: ÉXITO. El hash coincide.");
        } else {
            System.out.println("Verificación de integridad: FALLO. El hash NO coincide.");
            System.out.println("Hash esperado: " + hashService.bytesToHex(storedHash));
            System.out.println("Hash calculado: " + hashService.bytesToHex(newHash));
        }
    }

    public byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        // Generate a random AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        // Encrypt the data with AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = keyService.generateIV();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encryptedData = aesCipher.doFinal(data);

        // Encrypt the AES key with RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Combine everything into a single byte array
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        
        // Write the length of the encrypted key as a 4-byte integer
        outputStream.write((encryptedKey.length >>> 24) & 0xFF);
        outputStream.write((encryptedKey.length >>> 16) & 0xFF);
        outputStream.write((encryptedKey.length >>> 8) & 0xFF);
        outputStream.write((encryptedKey.length >>> 0) & 0xFF);
        
        outputStream.write(encryptedKey);        // Write the encrypted key
        outputStream.write(iv);                 // Write the IV
        outputStream.write(encryptedData);      // Write the encrypted data

        return outputStream.toByteArray();
    }

    public byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(encryptedData);

        // Read the encrypted key length as a 4-byte integer
        int keyLength = (inputStream.read() << 24) + (inputStream.read() << 16) + (inputStream.read() << 8) + (inputStream.read() << 0);
        byte[] encryptedKey = new byte[keyLength];
        inputStream.read(encryptedKey);

        // Read the IV
        byte[] iv = new byte[CryptoConstants.IV_LENGTH_BYTES];
        inputStream.read(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Read the encrypted data
        byte[] data = new byte[inputStream.available()];
        inputStream.read(data);

        // Decrypt the AES key with RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = rsaCipher.doFinal(encryptedKey);
        SecretKey aesKey = new SecretKeySpec(decryptedKey, "AES");

        // Decrypt the data with AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        return aesCipher.doFinal(data);
    }
}