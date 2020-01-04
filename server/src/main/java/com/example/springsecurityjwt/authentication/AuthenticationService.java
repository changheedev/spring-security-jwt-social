package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import org.springframework.security.core.userdetails.UserDetails;

public interface AuthenticationService {

    UserDetails authenticateUsernamePassword(String username, String password);
    UserDetails loadUser(String registrationId, OAuth2UserInfo userInfo);
    UserDetails linkAccount(String targetUsername, String registrationId, OAuth2UserInfo userInfo);
    void unlinkAccount(String provider, OAuth2UserInfo userInfo, Long userId);
}
