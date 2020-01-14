package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.authentication.oauth2.OAuth2Token;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountDTO;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface UserService {
    void signUpService(SignUpRequest signUpRequest);

    void updateProfile(String username, UpdateProfileRequest updateProfileRequest);

    UserDetails loginOAuth2User(String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo);

    Optional<OAuth2AccountDTO> getOAuth2Account(String username);

    UserDetails linkOAuth2Account(String username, String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo);

    OAuth2AccountDTO unlinkOAuth2Account(String username);

    Optional<OAuth2AccountDTO> withdrawUser(String username);
}
