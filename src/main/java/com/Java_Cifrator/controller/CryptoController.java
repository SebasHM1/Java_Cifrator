package com.Java_Cifrator.controller;

import com.Java_Cifrator.service.CryptoService;
import com.Java_Cifrator.service.FileHandler;
import com.Java_Cifrator.service.KeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/crypto")
@CrossOrigin(origins = "*")
public class CryptoController {

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private KeyService keyService;

    @Autowired
    private FileHandler fileHandler;

    @PostMapping("/encrypt")
    public ResponseEntity<Resource> encryptFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("publicKey") String publicKeyBase64) {
        try {
            // Decode the public key
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
            PublicKey publicKey = keyService.getPublicKeyFromBytes(publicKeyBytes);

            // Process the file
            byte[] fileContent = file.getBytes();
            byte[] encryptedContent = cryptoService.encrypt(fileContent, publicKey);

            // Create response
            ByteArrayResource resource = new ByteArrayResource(encryptedContent);
            
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=encrypted_" + file.getOriginalFilename())
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .contentLength(encryptedContent.length)
                    .body(resource);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<Resource> decryptFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("privateKey") String privateKeyBase64) {
        try {
            // Decode the private key
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
            KeyPair keyPair = keyService.getKeyPairFromPrivateKeyBytes(privateKeyBytes);

            // Process the file
            byte[] fileContent = file.getBytes();
            byte[] decryptedContent = cryptoService.decrypt(fileContent, keyPair.getPrivate());

            // Create response
            ByteArrayResource resource = new ByteArrayResource(decryptedContent);
            
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=decrypted_" + file.getOriginalFilename())
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .contentLength(decryptedContent.length)
                    .body(resource);
        } catch (Exception e) {
            // Devuelve el mensaje de error en el body
            return ResponseEntity.badRequest()
                .header(HttpHeaders.CONTENT_TYPE, "text/plain")
                .body(new ByteArrayResource(e.getMessage().getBytes()));
        }
    }

    @GetMapping("/generate-keys")
    public ResponseEntity<Map<String, String>> generateKeys() {
        try {
            KeyPair keyPair = keyService.generateKeyPair();
            
            Map<String, String> response = new HashMap<>();
            response.put("publicKey", Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            response.put("privateKey", Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }
} 