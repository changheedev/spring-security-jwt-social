package com.example.springsecurityjwt.authentication.oauth2.account;

import com.example.springsecurityjwt.users.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface OAuth2AccountRepository extends JpaRepository<OAuth2Account, Long> {

    Optional<OAuth2Account> findByUser(User user);
    Optional<OAuth2Account> findByProviderAndUserId(String provider, Long userId);
    Optional<OAuth2Account> findByProviderAndProviderId(String provider, String providerId);
    Optional<OAuth2Account> findByProviderAndProviderIdAndUserId(String provider, String providerId, Long userId);
    boolean existsByUser(User user);
    boolean existsByProviderAndProviderId(String provider, String providerId);
}
