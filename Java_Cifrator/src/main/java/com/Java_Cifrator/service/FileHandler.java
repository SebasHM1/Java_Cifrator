package com.Java_Cifrator.service;

import org.springframework.stereotype.Service;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

@Service
public class FileHandler {
    public byte[] readBytes(String filePath) throws IOException {
        return Files.readAllBytes(Paths.get(filePath));
    }

    public void writeBytes(String filePath, byte[] data) throws IOException {
        Files.write(Paths.get(filePath), data);
    }
}