package com.example.springsecurityjwt.authentication.oauth2.account;

import org.springframework.data.jpa.repository.JpaRepository;

public interface TempOAuth2AccountRepository extends JpaRepository<TempOAuth2Account, Long> {
}
