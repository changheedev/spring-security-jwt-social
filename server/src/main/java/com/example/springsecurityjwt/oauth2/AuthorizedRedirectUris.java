package com.example.springsecurityjwt.oauth2;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Getter
@Setter
@ConfigurationProperties(prefix = "spring.security.oauth2")
public class AuthorizedRedirectUris {
    private List<String> authorizedRedirectUris;
}
