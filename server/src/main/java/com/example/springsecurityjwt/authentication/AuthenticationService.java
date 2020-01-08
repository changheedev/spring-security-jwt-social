package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.authentication.oauth2.OAuth2Token;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountDTO;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import org.springframework.security.core.userdetails.UserDetails;

public interface AuthenticationService {

    UserDetails authenticateUsernamePassword(String username, String password);

    UserDetails registerOrLoadOAuth2User(String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo);

    UserDetails linkOAuth2Account(String targetUsername, String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo);

    OAuth2AccountDTO loadOAuth2Account(String provider, Long userId);

    void unlinkOAuth2Account(String provider, String providerId, Long userId);
}
