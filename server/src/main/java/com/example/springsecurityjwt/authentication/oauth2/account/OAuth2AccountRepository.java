package com.example.springsecurityjwt.authentication.oauth2.account;

import com.example.springsecurityjwt.users.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface OAuth2AccountRepository extends JpaRepository<OAuth2Account, Long> {

    boolean existsByProviderAndProviderId(String provider, String providerId);
    Optional<OAuth2Account> findByProviderAndProviderId(String provider, String providerId);
    List<OAuth2Account> findAllByUser(User user);
    void deleteByProviderAndUserId(String registrationId, Long userId);
}
