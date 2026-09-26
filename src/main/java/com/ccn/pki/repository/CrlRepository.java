package com.ccn.pki.repository;

import com.ccn.pki.model.CrlEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CrlRepository extends JpaRepository<CrlEntity, Long> {

    Optional<CrlEntity> findFirstByOrderByCrlNumberDesc();
}
