package com.ccn.pki.dto;

import com.ccn.pki.model.CertificateStatus;

import java.util.ArrayList;
import java.util.List;

/**
 * Rapport de résultat de validation d'un certificat X.509
 */
public class ValidationResult {

    private boolean valid;
    private CertificateStatus status;
    private String message;

    private String subjectDn;
    private String issuerDn;
    private String serialNumber;
    private String notBefore;
    private String notAfter;
    private String signatureAlgorithm;
    private String sha256Fingerprint;

    private boolean formatValid;
    private boolean timeValid;
    private boolean signatureValid;
    private boolean notRevoked;

    private String revocationDate;
    private String revocationReason;

    private List<String> extensions = new ArrayList<>();
    private List<String> diagnosticLogs = new ArrayList<>();

    public ValidationResult() {
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public CertificateStatus getStatus() {
        return status;
    }

    public void setStatus(CertificateStatus status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getSubjectDn() {
        return subjectDn;
    }

    public void setSubjectDn(String subjectDn) {
        this.subjectDn = subjectDn;
    }

    public String getIssuerDn() {
        return issuerDn;
    }

    public void setIssuerDn(String issuerDn) {
        this.issuerDn = issuerDn;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public String getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(String notAfter) {
        this.notAfter = notAfter;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getSha256Fingerprint() {
        return sha256Fingerprint;
    }

    public void setSha256Fingerprint(String sha256Fingerprint) {
        this.sha256Fingerprint = sha256Fingerprint;
    }

    public boolean isFormatValid() {
        return formatValid;
    }

    public void setFormatValid(boolean formatValid) {
        this.formatValid = formatValid;
    }

    public boolean isTimeValid() {
        return timeValid;
    }

    public void setTimeValid(boolean timeValid) {
        this.timeValid = timeValid;
    }

    public boolean isSignatureValid() {
        return signatureValid;
    }

    public void setSignatureValid(boolean signatureValid) {
        this.signatureValid = signatureValid;
    }

    public boolean isNotRevoked() {
        return notRevoked;
    }

    public void setNotRevoked(boolean notRevoked) {
        this.notRevoked = notRevoked;
    }

    public String getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(String revocationDate) {
        this.revocationDate = revocationDate;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }

    public List<String> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<String> extensions) {
        this.extensions = extensions;
    }

    public List<String> getDiagnosticLogs() {
        return diagnosticLogs;
    }

    public void setDiagnosticLogs(List<String> diagnosticLogs) {
        this.diagnosticLogs = diagnosticLogs;
    }

    public void addLog(String log) {
        this.diagnosticLogs.add(log);
    }
}
