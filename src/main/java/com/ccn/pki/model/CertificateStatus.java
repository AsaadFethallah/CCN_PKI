package com.ccn.pki.model;

/**
 * Statut d'un certificat émis par l'autorité de certification
 */
public enum CertificateStatus {
    ACTIVE("Actif", "Le certificat est valide et utilisable."),
    REVOKED("Révoqué", "Le certificat a été révoqué et figure dans la CRL."),
    EXPIRED("Expiré", "La période de validité du certificat a expiré.");

    private final String label;
    private final String description;

    CertificateStatus(String label, String description) {
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
