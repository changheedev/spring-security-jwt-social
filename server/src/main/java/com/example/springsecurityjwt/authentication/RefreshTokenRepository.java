package com.example.springsecurityjwt.authentication;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByUsername(String username);
    boolean existsByUsername(String username);
    void deleteByUsername(String username);
}
