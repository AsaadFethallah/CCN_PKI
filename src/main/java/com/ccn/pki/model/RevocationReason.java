package com.ccn.pki.model;

import org.bouncycastle.asn1.x509.CRLReason;

/**
 * Raisons de révocation selon le standard RFC 5280 (Section 5.3.1)
 */
public enum RevocationReason {
    UNSPECIFIED(CRLReason.unspecified, "Non spécifié (unspecified)"),
    KEY_COMPROMISE(CRLReason.keyCompromise, "Compromission de la clé privée (keyCompromise)"),
    CA_COMPROMISE(CRLReason.cACompromise, "Compromission de l'autorité (cACompromise)"),
    AFFILIATION_CHANGED(CRLReason.affiliationChanged, "Changement d'affiliation (affiliationChanged)"),
    SUPERSEDED(CRLReason.superseded, "Remplacé par un nouveau certificat (superseded)"),
    CESSATION_OF_OPERATION(CRLReason.cessationOfOperation, "Cessation d'activité (cessationOfOperation)"),
    CERTIFICATE_HOLD(CRLReason.certificateHold, "Suspension temporaire (certificateHold)");

    private final int code;
    private final String description;

    RevocationReason(int code, String description) {
        this.code = code;
        this.description = description;
    }

    public int getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }
}
