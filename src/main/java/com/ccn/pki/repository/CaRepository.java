package com.ccn.pki.repository;

import com.ccn.pki.model.CaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CaRepository extends JpaRepository<CaEntity, Long> {

    Optional<CaEntity> findFirstByActiveTrueOrderByCreatedAtDesc();

    Optional<CaEntity> findBySerialNumber(String serialNumber);
}
