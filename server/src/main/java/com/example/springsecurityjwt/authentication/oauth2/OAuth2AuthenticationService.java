package com.example.springsecurityjwt.authentication.oauth2;

import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import org.springframework.security.core.userdetails.UserDetails;

public interface OAuth2AuthenticationService {

    String getOAuth2AccessToken(ClientRegistration clientRegistration, String code, String state);
    OAuth2UserInfo getOAuth2UserInfo(ClientRegistration clientRegistration, String accessToken);
    UserDetails loadUser(String registrationId, OAuth2UserInfo userInfo);
    UserDetails linkAccount(String targetUsername, String registrationId, OAuth2UserInfo userInfo);
    void unlinkAccount(ClientRegistration clientRegistration, String accessToken, OAuth2UserInfo userInfo, Long userId);
}
