package com.ccn.pki.service;

import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

/**
 * Service de génération de biclés asymétriques (RSA)
 */
@Service
public class KeyGenerationService {

    private static final String ALGORITHM = "RSA";
    private static final String PROVIDER = "BC";

    /**
     * Génère une paire de clés RSA avec la taille spécifiée (ex: 2048, 4096 bits)
     */
    public KeyPair generateRsaKeyPair(int keySize) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        SecureRandom random = new SecureRandom();
        generator.initialize(keySize, random);
        return generator.generateKeyPair();
    }
}
