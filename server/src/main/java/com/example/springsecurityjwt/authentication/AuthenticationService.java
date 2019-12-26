package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.jwt.JWT;
import org.springframework.security.core.userdetails.UserDetails;

public interface AuthenticationService {

    UserDetails authenticateUsernamePassword(String username, String password);
    JWT issueToken(String username);
    JWT refreshAccessToken(String oldToken, String refreshToken);
    void expiredRefreshToken(String username);
}
