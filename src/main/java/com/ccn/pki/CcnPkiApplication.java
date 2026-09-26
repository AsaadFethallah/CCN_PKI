package com.ccn.pki;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import java.security.Security;

/**
 * ===================================================================
 * Application Principale : CCN_PKI
 * Infrastructure à Clés Publiques (PKI) - MVP Option B
 * Conçue pour le module Confiance Numérique et Accès Biométrique (ENSET)
 * ===================================================================
 *
 * Ce projet implémente une autorité de certification racine (Root CA)
 * minimale mais complète et conforme à la RFC 5280 :
 * - Génération de biclé RSA et certificat auto-signé Root CA.
 * - Émission et signature de certificats clients/serveurs avec extensions X.509v3.
 * - Support de la signature directe ou par Certificate Signing Request (CSR PKCS#10).
 * - Révocation de certificats avec motif RFC 5280 et publication de CRL X.509v2.
 * - Moteur de validation cryptographique (temporalité, signature, CRL check).
 * - Intégration et validation avec OpenSSL.
 */
@SpringBootApplication
@EnableConfigurationProperties
public class CcnPkiApplication {

    static {
        // Enregistrement du fournisseur de cryptographie Bouncy Castle au démarrage
        // Indispensable pour la manipulation des certificats X.509 v3, CRL v2, et algorithmes avancés
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(CcnPkiApplication.class, args);
    }
}
