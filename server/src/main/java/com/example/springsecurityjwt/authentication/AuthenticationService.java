package com.example.springsecurityjwt.authentication;

public interface AuthenticationService {

    UserDetails authenticateUsernamePassword(String username, String password);
    AccessTokenResponse issueToken(String username);
    AccessTokenResponse refreshAccessToken(String oldToken, String refreshToken);
    void expiredRefreshToken(String username);
}
