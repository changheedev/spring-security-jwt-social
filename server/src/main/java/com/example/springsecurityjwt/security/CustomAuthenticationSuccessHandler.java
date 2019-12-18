package com.example.springsecurityjwt.security;

import com.example.springsecurityjwt.authentication.AccessTokenResponse;
import com.example.springsecurityjwt.jwt.JwtProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private JwtProvider jwtProvider;
    private ObjectMapper objectMapper;

    public CustomAuthenticationSuccessHandler(JwtProvider jwtProvider, ObjectMapper objectMapper) {
        this.jwtProvider = jwtProvider;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        CustomUserDetails userDetails = (CustomUserDetails)authentication.getPrincipal();
        AccessTokenResponse accessTokenResponse = AccessTokenResponse.builder()
                .token(jwtProvider.generateToken(userDetails))
                .refreshToken(jwtProvider.generateRefreshToken(userDetails))
                .build();

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(accessTokenResponse));
        response.setStatus(200);
    }
}
