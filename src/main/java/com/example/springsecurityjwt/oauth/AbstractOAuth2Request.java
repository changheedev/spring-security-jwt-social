package com.example.springsecurityjwt.oauth;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

@Getter
@Setter
public class AbstractOAuth2Request {
    private ClientRegistration clientRegistration;

    public AbstractOAuth2Request(ClientRegistration clientRegistration) {
        this.clientRegistration = clientRegistration;
    }
}
