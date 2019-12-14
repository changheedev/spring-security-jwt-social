package com.example.springsecurityjwt.oauth;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

@Getter
@Setter
public class OAuth2UserInfoRequest extends AbstractOAuth2Request{

    private String AccessToken;

    @Builder
    public OAuth2UserInfoRequest(ClientRegistration clientRegistration, String accessToken) {
        super(clientRegistration);
        AccessToken = accessToken;
    }
}
