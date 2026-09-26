package com.ccn.pki.dto;

import com.ccn.pki.model.CertificateType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Formulaire de demande d'émission d'un certificat (avec génération de clé côté serveur)
 */
public class IssueCertificateRequest {

    @NotBlank(message = "Le Common Name (CN) est obligatoire.")
    private String commonName;

    private String organization = "ENSET Mohammedia";
    private String organizationalUnit = "Etudiant";
    private String country = "MA";
    private String email;

    private int validityDays = 365;
    private int keySize = 2048;

    @NotNull(message = "Le type de certificat est obligatoire.")
    private CertificateType type = CertificateType.CLIENT;

    // Noms alternatifs (SAN) séparés par des virgules (ex: localhost, 127.0.0.1, api.domain.local)
    private String subjectAlternativeNames;

    // Mot de passe pour protéger le conteneur PKCS#12 (.p12)
    private String pkcs12Password;

    public IssueCertificateRequest() {
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getOrganizationalUnit() {
        return organizationalUnit;
    }

    public void setOrganizationalUnit(String organizationalUnit) {
        this.organizationalUnit = organizationalUnit;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public int getValidityDays() {
        return validityDays;
    }

    public void setValidityDays(int validityDays) {
        this.validityDays = validityDays;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public CertificateType getType() {
        return type;
    }

    public void setType(CertificateType type) {
        this.type = type;
    }

    public String getSubjectAlternativeNames() {
        return subjectAlternativeNames;
    }

    public void setSubjectAlternativeNames(String subjectAlternativeNames) {
        this.subjectAlternativeNames = subjectAlternativeNames;
    }

    public String getPkcs12Password() {
        return pkcs12Password;
    }

    public void setPkcs12Password(String pkcs12Password) {
        this.pkcs12Password = pkcs12Password;
    }
}
