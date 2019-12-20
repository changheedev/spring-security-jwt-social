package com.example.springsecurityjwt.authentication;

public interface AuthenticationService {

    UserDetails authenticateUsernamePassword(String username, String password);
    AccessTokenResponse issueAccessToken(UserDetails userDetails);
    AccessTokenResponse refreshAccessToken(String refreshToken);
    void expiredRefreshToken(String username);
}
