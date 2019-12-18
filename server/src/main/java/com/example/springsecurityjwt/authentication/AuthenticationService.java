package com.example.springsecurityjwt.authentication;

public interface AuthenticationService {

    String generateAuthorizationCode(String username) throws Exception;
    AccessTokenResponse exchangeAuthorizationCodeToAccessToken(String code, String username) throws Exception;
    AccessTokenResponse refreshAuthenticationToken(String refreshToken, String username) throws Exception;
}
