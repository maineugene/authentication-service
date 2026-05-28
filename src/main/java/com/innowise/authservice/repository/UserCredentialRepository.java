package com.innowise.authservice.repository;

import com.innowise.authservice.model.UserCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserCredentialRepository extends JpaRepository<UserCredential, Long> {

    Optional<UserCredential> findByLogin(String login);

    Optional<UserCredential> findByUserId(Long userId);

    boolean existsByLogin(String login);
}
