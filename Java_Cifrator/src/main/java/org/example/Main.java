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

public class FileEncryptorDecryptor {

    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding"; // CBC necesita un IV
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final int KEY_LENGTH_BITS = 256;
    private static final int ITERATION_COUNT = 65536; // Estándar recomendado
    private static final int SALT_LENGTH_BYTES = 16; // 128 bits para el salt
    private static final int IV_LENGTH_BYTES = 16;  // 128 bits para el IV (AES block size)

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

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
            } else if (choice == 2) {
                decryptFile(inputFile, outputFile, password);
            } else {
                System.out.println("Opción no válida.");
            }
        } catch (Exception e) {
            System.err.println("Error durante la operación: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
    // ... (métodos de cifrado y descifrado irán aquí)
}