package com.example.springsecurityjwt.authentication.oauth2;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

@Getter
@Setter
public class OAuth2AccessTokenRequest extends AbstractOAuth2Request{

    private String state;
    private String code;
    private String redirectUri;

    @Builder
    public OAuth2AccessTokenRequest(ClientRegistration clientRegistration, String state, String code, String redirectUri) {
        super(clientRegistration);
        this.state = state;
        this.code = code;
        this.redirectUri = redirectUri;
    }
}
