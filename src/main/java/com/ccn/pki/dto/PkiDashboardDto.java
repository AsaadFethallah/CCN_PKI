package com.ccn.pki.dto;

import com.ccn.pki.model.CaEntity;
import com.ccn.pki.model.CertificateEntity;
import com.ccn.pki.model.CrlEntity;

import java.util.List;

/**
 * DTO regroupant les statistiques et données du tableau de bord
 */
public class PkiDashboardDto {

    private long totalCertificates;
    private long activeCertificates;
    private long revokedCertificates;
    private long expiredCertificates;

    private CaEntity ca;
    private CrlEntity latestCrl;
    private List<CertificateEntity> recentCertificates;

    public PkiDashboardDto() {
    }

    public long getTotalCertificates() {
        return totalCertificates;
    }

    public void setTotalCertificates(long totalCertificates) {
        this.totalCertificates = totalCertificates;
    }

    public long getActiveCertificates() {
        return activeCertificates;
    }

    public void setActiveCertificates(long activeCertificates) {
        this.activeCertificates = activeCertificates;
    }

    public long getRevokedCertificates() {
        return revokedCertificates;
    }

    public void setRevokedCertificates(long revokedCertificates) {
        this.revokedCertificates = revokedCertificates;
    }

    public long getExpiredCertificates() {
        return expiredCertificates;
    }

    public void setExpiredCertificates(long expiredCertificates) {
        this.expiredCertificates = expiredCertificates;
    }

    public CaEntity getCa() {
        return ca;
    }

    public void setCa(CaEntity ca) {
        this.ca = ca;
    }

    public CrlEntity getLatestCrl() {
        return latestCrl;
    }

    public void setLatestCrl(CrlEntity latestCrl) {
        this.latestCrl = latestCrl;
    }

    public List<CertificateEntity> getRecentCertificates() {
        return recentCertificates;
    }

    public void setRecentCertificates(List<CertificateEntity> recentCertificates) {
        this.recentCertificates = recentCertificates;
    }
}
