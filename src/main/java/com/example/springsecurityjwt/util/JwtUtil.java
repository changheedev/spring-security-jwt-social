package com.example.springsecurityjwt.util;


import com.example.springsecurityjwt.dto.UserDetailsDTO;
import com.example.springsecurityjwt.security.jwt.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    private JwtProperties jwtProperties;

    public JwtUtil(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private LocalDateTime extractExpiration(String token) {
        return LocalDateTime.ofInstant(extractClaim(token, Claims::getExpiration).toInstant(), ZoneId.systemDefault());
    }

    private <T> T extractClaim (String token , Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(jwtProperties.getSecretKey()).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).isBefore(LocalDateTime.now());
    }

    public String generateToken(UserDetailsDTO userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", userDetails.getId());
        claims.put("name", userDetails.getName());
        return createToken(claims, userDetails.getUsername(), jwtProperties.getTokenExpired());
    }

    public String generateRefreshToken(UserDetailsDTO userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername(), jwtProperties.getRefreshTokenExpired());
    }

    private String createToken(Map<String, Object> claims, String subject, Long expiryTime) {
        LocalDateTime expiryDate = LocalDateTime.now().plusSeconds(expiryTime);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant()))
                .setExpiration(Date.from(expiryDate.atZone(ZoneId.systemDefault()).toInstant()))
                .signWith(jwtProperties.getSignatureAlgorithm(), jwtProperties.getSecretKey())
                .compact();
    }

    public boolean validateToken(String token, UserDetailsDTO userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}