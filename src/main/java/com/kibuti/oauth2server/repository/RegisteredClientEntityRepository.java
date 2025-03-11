package com.kibuti.oauth2server.repository;

import com.kibuti.oauth2server.entity.RegisteredClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RegisteredClientEntityRepository extends JpaRepository<RegisteredClientEntity, String> {

    Optional<RegisteredClientEntity> findByClientId(String clientId);

    List<RegisteredClientEntity> findByOwnerUsername(String username);

    Optional<RegisteredClientEntity> findByClientIdAndOwnerUsername(String clientId, String username);

    long countByApprovedFalse();

    List<RegisteredClientEntity> findTop10ByApprovedFalseOrderByClientIdIssuedAtDesc();

    List<RegisteredClientEntity> findByOwnerId(UUID ownerId);
}