package com.ccn.pki.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité enregistrant l'historique et la version courante de la Liste de Révocation (CRL)
 */
@Entity
@Table(name = "crl_records")
public class CrlEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long crlNumber;

    @Column(nullable = false)
    private LocalDateTime thisUpdate;

    @Column(nullable = false)
    private LocalDateTime nextUpdate;

    @Lob
    @Column(nullable = false, columnDefinition = "TEXT")
    private String crlPem;

    @Column(nullable = false)
    private int revokedCount;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    public CrlEntity() {
    }

    public CrlEntity(Long crlNumber, LocalDateTime thisUpdate, LocalDateTime nextUpdate, String crlPem, int revokedCount) {
        this.crlNumber = crlNumber;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.crlPem = crlPem;
        this.revokedCount = revokedCount;
        this.createdAt = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getCrlNumber() {
        return crlNumber;
    }

    public void setCrlNumber(Long crlNumber) {
        this.crlNumber = crlNumber;
    }

    public LocalDateTime getThisUpdate() {
        return thisUpdate;
    }

    public void setThisUpdate(LocalDateTime thisUpdate) {
        this.thisUpdate = thisUpdate;
    }

    public LocalDateTime getNextUpdate() {
        return nextUpdate;
    }

    public void setNextUpdate(LocalDateTime nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    public String getCrlPem() {
        return crlPem;
    }

    public void setCrlPem(String crlPem) {
        this.crlPem = crlPem;
    }

    public int getRevokedCount() {
        return revokedCount;
    }

    public void setRevokedCount(int revokedCount) {
        this.revokedCount = revokedCount;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
