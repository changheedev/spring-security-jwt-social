package com.example.springsecurityjwt.oauth;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

@Getter
@Setter
public class OAuth2AccessTokenRequest extends AbstractOAuth2Request{

    private String state;
    private String code;

    @Builder
    public OAuth2AccessTokenRequest(ClientRegistration clientRegistration, String state, String code) {
        super(clientRegistration);
        this.state = state;
        this.code = code;
    }
}
