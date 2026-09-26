package com.ccn.pki.repository;

import com.ccn.pki.model.RevocationEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RevocationRepository extends JpaRepository<RevocationEntity, Long> {

    Optional<RevocationEntity> findBySerialNumber(String serialNumber);

    List<RevocationEntity> findAllByOrderByRevocationDateDesc();

    boolean existsBySerialNumber(String serialNumber);
}
