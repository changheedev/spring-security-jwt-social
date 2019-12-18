package com.example.springsecurityjwt.authentication.oauth2;

import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;

public interface OAuth2AuthenticationService {

    boolean findOAuth2Account(String registrationId, String providerId);
    String getOAuth2AccessToken(OAuth2AccessTokenRequest oAuth2AccessTokenRequest);
    OAuth2UserInfo getOAuth2UserInfo(OAuth2UserInfoRequest oAuth2UserInfoRequest);
    UserDetails loadUser(String registrationId, OAuth2UserInfo userInfo);
    UserDetails linkAccount(String targetUsername, String registrationId, OAuth2UserInfo userInfo);
    Long saveAsTemporaryAccount(String registrationId, OAuth2UserInfo userInfo);
    UserDetails completeTemporaryAccountAuthorization(Long tid, Map<String, Object> attributes);
}
