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

    public byte[] encryptFile(byte[] fileBytes, String password) throws Exception {
        byte[] originalHash = hashService.calculateSHA256(fileBytes);

        byte[] salt = keyService.generateSalt();
        SecretKey secretKey = keyService.generateKey(password, salt);
        byte[] iv = keyService.generateIV();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(CryptoConstants.AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            baos.write(salt);
            baos.write(iv);
            baos.write(originalHash);
            baos.write(encryptedBytes);
            return baos.toByteArray();
        }
    }

    public byte[] decryptFileAndVerify(byte[] encryptedFileBytes, String password) throws Exception {

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

        //fileHandler.writeBytes(outputFilePath, decryptedBytes);
        //System.out.println("Archivo descifrado (maybe) en: " + outputFilePath);

        byte[] newHash = hashService.calculateSHA256(decryptedBytes);
        boolean integrityCheck = Arrays.equals(newHash, storedHash);

        if (integrityCheck) {
            System.out.println("Verificación de integridad: ÉXITO. El hash coincide.");
        } else {
            System.out.println("Verificación de integridad: FALLO. El hash NO coincide.");
            System.out.println("Hash esperado: " + hashService.bytesToHex(storedHash));
            System.out.println("Hash calculado: " + hashService.bytesToHex(newHash));
        }

        return decryptedBytes;
    }
}