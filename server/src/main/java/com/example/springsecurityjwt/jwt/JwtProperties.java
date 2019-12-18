package com.example.springsecurityjwt.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String secretKey;
    private SignatureAlgorithm signatureAlgorithm;
    private Long tokenExpired;
    private Long refreshTokenExpired;
}
