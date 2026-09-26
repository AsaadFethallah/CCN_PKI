package com.ccn.pki.dto;

import com.ccn.pki.model.RevocationReason;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Requête de révocation d'un certificat
 */
public class RevokeCertificateRequest {

    @NotBlank(message = "Le numéro de série du certificat est obligatoire.")
    private String serialNumber;

    @NotNull(message = "La raison de révocation est obligatoire.")
    private RevocationReason reason = RevocationReason.KEY_COMPROMISE;

    private String comments;

    public RevokeCertificateRequest() {
    }

    public RevokeCertificateRequest(String serialNumber, RevocationReason reason, String comments) {
        this.serialNumber = serialNumber;
        this.reason = reason;
        this.comments = comments;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public RevocationReason getReason() {
        return reason;
    }

    public void setReason(RevocationReason reason) {
        this.reason = reason;
    }

    public String getComments() {
        return comments;
    }

    public void setComments(String comments) {
        this.comments = comments;
    }
}
