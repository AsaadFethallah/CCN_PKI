package com.ccn.pki.dto;

import com.ccn.pki.model.CertificateType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Requête de signature d'une CSR (PKCS#10 Certificate Signing Request)
 */
public class IssueCsrRequest {

    @NotBlank(message = "La demande CSR au format PEM est requise.")
    private String csrPem;

    private int validityDays = 365;

    @NotNull(message = "Le type de certificat est obligatoire.")
    private CertificateType type = CertificateType.SERVER;

    private String subjectAlternativeNames;

    public IssueCsrRequest() {
    }

    public String getCsrPem() {
        return csrPem;
    }

    public void setCsrPem(String csrPem) {
        this.csrPem = csrPem;
    }

    public int getValidityDays() {
        return validityDays;
    }

    public void setValidityDays(int validityDays) {
        this.validityDays = validityDays;
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
}
