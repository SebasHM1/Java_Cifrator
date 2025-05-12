package com.Java_Cifrator;

import com.Java_Cifrator.core.CryptoConstants;
import com.Java_Cifrator.service.FileHandler;
import com.Java_Cifrator.service.HashService;
import com.Java_Cifrator.service.KeyService;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class MainApp {

    private static final String PBKDF2_ALGORITHM = CryptoConstants.PBKDF2_ALGORITHM;
    private static final String AES_ALGORITHM = CryptoConstants.AES_ALGORITHM; // CBC necesita un IV
    private static final String HASH_ALGORITHM = CryptoConstants.HASH_ALGORITHM;
    private static final int KEY_LENGTH_BITS = CryptoConstants.KEY_LENGTH_BITS;
    private static final int ITERATION_COUNT = CryptoConstants.ITERATION_COUNT; // Estándar recomendado
    private static final int SALT_LENGTH_BYTES = CryptoConstants.SALT_LENGTH_BYTES; // 128 bits para el salt
    private static final int IV_LENGTH_BYTES = CryptoConstants.IV_LENGTH_BYTES;  // 128 bits para el IV (AES block size)
    private static final Scanner scanner = new Scanner(System.in);
    private static final HashService hashService = new HashService();
    private static final KeyService keyService = new KeyService();
    private static final FileHandler fileHandler = new FileHandler();
    public static void main(String[] args) {
        boolean exit = false;

        while (!exit) {
            try {
                exit = menu();
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace();
            }
        }

    }

    private static boolean menu () {

        System.out.println("Seleccione una opción:");
        System.out.println("1) Cifrar archivo");
        System.out.println("2) Descifrar archivo");
        System.out.print("Opción: ");
        int choice = Integer.parseInt(scanner.nextLine());

        System.out.print("Ingrese la ruta del archivo de entrada: ");
        String inputFile = scanner.nextLine();
        System.out.print("Ingrese la ruta del archivo de salida: ");
        String outputFile = scanner.nextLine();
        System.out.print("Ingrese la contraseña: ");
        String password = scanner.nextLine();

        try {
            if (choice == 1) {
                encryptFile(inputFile, outputFile, password);
                System.out.println("Archivo cifrado correctamente en: " + outputFile);
                return false;
            } else if (choice == 2) {
                decryptFile(inputFile, outputFile, password);
                return false;
            } else if (choice == 3) {
                System.out.println("Saliendo");
                return true;
            } else {
                System.out.println("Opción no válida, ingresela de nuevo");
                return false;
            }
        } catch (Exception e) {
            System.err.println("Error durante la operación: " + e.getMessage());
            e.printStackTrace();
            return false;
        }

    }

    public static void encryptFile(String inputFilePath, String outputFilePath, String password)
            throws Exception {

        byte[] fileBytes = fileHandler.readBytes(inputFilePath);
        byte[] originalHash = hashService.calculateSHA256(fileBytes);

        byte[] salt = keyService.generateSalt();
        SecretKey secretKey = keyService.generateKey(password, salt);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);

        byte[] iv = keyService.generateIV();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);

        // Escribir todo al archivo de salida
        // Formato: [salt (16 bytes)] [iv (16 bytes)] [hash (32 bytes)] [datos cifrados]
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(originalHash);
            fos.write(encryptedBytes);
        }
    }

    // Dentro de la clase FileEncryptorDecryptor

    public static void decryptFile(String inputFilePath, String outputFilePath, String password)
            throws Exception {

        byte[] encryptedFileBytes = fileHandler.readBytes(inputFilePath);

        // Extraer salt, IV, hash almacenado y datos cifrados
        // Asumimos que los tamaños son fijos como se definió
        ByteArrayInputStream bis = new ByteArrayInputStream(encryptedFileBytes);

        byte[] salt = new byte[SALT_LENGTH_BYTES];
        bis.read(salt);

        byte[] iv = new byte[IV_LENGTH_BYTES];
        bis.read(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        byte[] storedHash = new byte[32]; // SHA-256 tiene 32 bytes
        bis.read(storedHash);

        byte[] encryptedBytes = new byte[bis.available()];
        bis.read(encryptedBytes);
        bis.close();


        SecretKey secretKey = keyService.generateKey(password, salt);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] decryptedBytes;
        try {
            decryptedBytes = cipher.doFinal(encryptedBytes);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            System.err.println("Error al descifrar: Contraseña incorrecta o archivo corrupto.");
            throw e; // Re-lanzar para que el main lo capture
        }


        // Escribir archivo descifrado
        fileHandler.writeBytes(outputFilePath, decryptedBytes);
        System.out.println("Archivo descifrado (potencialmente) en: " + outputFilePath);

        // Verificar integridad
        byte[] newHash = hashService.calculateSHA256(decryptedBytes);

        if (Arrays.equals(newHash, storedHash)) {
            System.out.println("Verificación de integridad: ÉXITO. El hash coincide.");
        } else {
            System.out.println("Verificación de integridad: FALLO. El hash NO coincide.");
            System.out.println("Hash esperado: " + hashService.bytesToHex(storedHash));
            System.out.println("Hash calculado: " + hashService.bytesToHex(newHash));
        }
    }

}