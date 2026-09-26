package com.ccn.pki.model;

/**
 * Type et profil d'utilisation du certificat X.509
 */
public enum CertificateType {
    ROOT_CA("Autorité Racine (Root CA)", "Certificat auto-signé servant à signer d'autres certificats et les CRL"),
    CLIENT("Authentification Client / Utilisateur", "Certificat pour l'authentification mutuelle TLS et signature"),
    SERVER("Serveur Web / TLS", "Certificat SSL/TLS avec Subject Alternative Names pour sécuriser un serveur"),
    CODE_SIGNING("Signature de Code", "Certificat pour signer cryptographiquement des binaires et documents");

    private final String label;
    private final String description;

    CertificateType(String label, String description) {
        this.label = label;
        this.description = description;
    }

    public String getLabel() {
        return label;
    }

    public String getDescription() {
        return description;
    }
}
