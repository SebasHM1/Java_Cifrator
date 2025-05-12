package com.Java_Cifrator;

import com.Java_Cifrator.core.CryptoConstants;
import com.Java_Cifrator.service.CryptoService;
import com.Java_Cifrator.service.FileHandler;
import com.Java_Cifrator.service.HashService;
import com.Java_Cifrator.service.KeyService;


import java.util.Scanner;

public class MainApp {

    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {

            KeyService keyService = new KeyService();
            HashService hashService = new HashService();
            FileHandler fileHandler = new FileHandler();
            CryptoService cryptoService = new CryptoService(keyService, hashService, fileHandler);

            System.out.println("Bienvenido al cifrador de archivos");

            boolean exit = false;

            while (!exit) {
                try {
                    exit = menu(scanner, cryptoService);
                } catch (Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace();
                }
            }

        }

        System.out.println("Hasta pronto");

    }

    private static boolean menu (Scanner scanner, CryptoService cryptoService) throws Exception {

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
                cryptoService.encryptFile(inputFile, outputFile, password);
                System.out.println("Archivo cifrado correctamente en: " + outputFile);
                return false;
            } else if (choice == 2) {
                cryptoService.decryptFileAndVerify(inputFile, outputFile, password);
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

}