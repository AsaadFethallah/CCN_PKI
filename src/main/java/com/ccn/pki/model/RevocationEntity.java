package com.ccn.pki.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité enregistrant une révocation pour la construction de la CRL
 */
@Entity
@Table(name = "revocations")
public class RevocationEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String serialNumber;

    @Column(nullable = false)
    private LocalDateTime revocationDate = LocalDateTime.now();

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 40)
    private RevocationReason reason;

    @Column(length = 500)
    private String comments;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_id")
    private CertificateEntity certificate;

    public RevocationEntity() {
    }

    public RevocationEntity(String serialNumber, LocalDateTime revocationDate, RevocationReason reason, String comments, CertificateEntity certificate) {
        this.serialNumber = serialNumber;
        this.revocationDate = revocationDate;
        this.reason = reason;
        this.comments = comments;
        this.certificate = certificate;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public LocalDateTime getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(LocalDateTime revocationDate) {
        this.revocationDate = revocationDate;
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

    public CertificateEntity getCertificate() {
        return certificate;
    }

    public void setCertificate(CertificateEntity certificate) {
        this.certificate = certificate;
    }
}
