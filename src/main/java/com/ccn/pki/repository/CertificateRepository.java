package com.ccn.pki.repository;

import com.ccn.pki.model.CertificateEntity;
import com.ccn.pki.model.CertificateStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<CertificateEntity, Long> {

    Optional<CertificateEntity> findBySerialNumber(String serialNumber);

    List<CertificateEntity> findByStatus(CertificateStatus status);

    List<CertificateEntity> findAllByOrderByIssuedAtDesc();

    long countByStatus(CertificateStatus status);
}
