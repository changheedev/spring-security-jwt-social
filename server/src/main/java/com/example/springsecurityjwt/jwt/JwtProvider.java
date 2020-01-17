package com.example.springsecurityjwt.jwt;


import com.example.springsecurityjwt.util.DateConvertor;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final JwtProperties jwtProperties;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public LocalDateTime extractExpiration(String token) {
        return DateConvertor.toLocalDateTime(extractClaim(token, Claims::getExpiration));
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(jwtProperties.getSecretKey()).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).isBefore(LocalDateTime.now());
    }

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return generateToken(claims, username, jwtProperties.getTokenExpired());
    }

    private String generateToken(Map<String, Object> claims, String subject, Long expiryTime) {
        LocalDateTime expiryDate = LocalDateTime.now().plusSeconds(expiryTime);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(DateConvertor.toDate(LocalDateTime.now()))
                .setExpiration(DateConvertor.toDate(expiryDate))
                .signWith(jwtProperties.getSignatureAlgorithm(), jwtProperties.getSecretKey())
                .compact();
    }

    public boolean validateToken(String token, String username) {
        final String tokenUsername = extractUsername(token);
        return (username.equals(tokenUsername) && !isTokenExpired(token));
    }

    public Long getTokenExpirationDate() {
        return jwtProperties.getTokenExpired();
    }

}