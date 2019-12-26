package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.SpringTestSupport;
import com.example.springsecurityjwt.jwt.JWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AuthenticationServiceTest extends SpringTestSupport {

    @Autowired
    private AuthenticationService authenticationService;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Test
    public void refreshToken_만료시간_테스트() {

        JWT token = authenticationService.issueToken("abc@email.com");
        RefreshToken entityRefreshToken = refreshTokenRepository.findByUsernameAndRefreshToken("abc@email.com", token.getRefreshToken()).get();

        assertFalse(entityRefreshToken.isExpired());
        assertTrue(entityRefreshToken.getExpiredAt().isAfter(LocalDateTime.now().plusDays(59)));
    }
}
