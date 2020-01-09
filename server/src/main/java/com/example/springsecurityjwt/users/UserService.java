package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.authentication.oauth2.OAuth2Token;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountDTO;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface UserService {
    void signUpService(SignUpRequest signUpRequest);

    Optional<OAuth2AccountDTO> getOAuth2Account(String username);

    void updateProfile(String username, UpdateProfileRequest updateProfileRequest);

    UserDetails loginOAuth2User(String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo);

    UserDetails linkOAuth2Account(String targetUsername, String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo);

    void unlinkOAuth2Account(String username);

    void withdrawUser(String username);
}
