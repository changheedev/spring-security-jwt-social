package com.example.springsecurityjwt.authentication.oauth2;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.Collections;
import java.util.Set;

@Getter
@Setter
public final class ClientRegistration {
    private String registrationId;
    private String clientId;
    private String clientSecret;
    private String authorizationGrantType;
    private String redirectUri;
    private Set<String> scopes = Collections.emptySet();
    private ProviderDetails providerDetails = new ProviderDetails();

    @Builder
    public ClientRegistration(String registrationId, String clientId, String authorizationGrantType, String clientSecret, String redirectUri, Set<String> scopes, String authorizationUri, String tokenUri, String userInfoUri, String unlinkUri) {
        this.registrationId = registrationId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.authorizationGrantType = authorizationGrantType;
        this.redirectUri = redirectUri;
        this.scopes = scopes;
        this.providerDetails.authorizationUri = authorizationUri;
        this.providerDetails.tokenUri = tokenUri;
        this.providerDetails.userInfoUri = userInfoUri;
        this.providerDetails.unlinkUri = unlinkUri;
    }

    @Getter
    @Setter
    public class ProviderDetails {
        private String authorizationUri;
        private String tokenUri;
        private String userInfoUri;
        private String unlinkUri;
    }
}