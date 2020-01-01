package com.example.springsecurityjwt.authentication.oauth2;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Component
@ConfigurationProperties(prefix = "spring.security.oauth2.client")
public class OAuth2ClientProperties {

    private final Map<String, Provider> provider = new HashMap<>();
    private final Map<String, Registration> registration = new HashMap<>();

    public Map<String, Provider> getProvider() {
        return this.provider;
    }
    public Map<String, Registration> getRegistration() {
        return this.registration;
    }

    /**
     * A single client registration.
     */
    @Getter
    @Setter
    public static class Registration {
        private String provider;
        private String clientId;
        private String clientSecret;
        private String authorizationGrantType;
        private String redirectUri;
        private Set<String> scope;
    }

    @Getter
    @Setter
    public static class Provider {
        private String authorizationUri;
        private String tokenUri;
        private String userInfoUri;
        private String unlinkUri;
    }
}