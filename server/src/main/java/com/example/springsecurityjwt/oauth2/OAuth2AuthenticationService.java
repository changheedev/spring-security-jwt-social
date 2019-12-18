package com.example.springsecurityjwt.oauth2;

import org.springframework.security.core.userdetails.UserDetails;

public interface OAuth2AuthenticationService {

    String getOAuth2AccessToken(OAuth2AccessTokenRequest oAuth2AccessTokenRequest);
    OAuth2UserInfo getOAuth2UserInfo(OAuth2UserInfoRequest oAuth2UserInfoRequest);
    UserDetails loadUser(String registrationId, OAuth2UserInfo userInfo);
    UserDetails linkAccount(String targetUsername, String registrationId, OAuth2UserInfo userInfo);
    boolean findOAuth2Account(String registrationId, String providerId);
}
