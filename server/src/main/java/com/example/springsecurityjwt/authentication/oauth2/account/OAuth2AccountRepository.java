package com.example.springsecurityjwt.authentication.oauth2.account;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuth2AccountRepository extends JpaRepository<OAuth2Account, Long> {

    boolean existsByProviderAndProviderId(String provider, String providerId);
    Optional<OAuth2Account> findByProviderAndProviderId(String provider, String providerId);
}
