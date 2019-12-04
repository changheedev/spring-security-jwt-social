package com.example.springsecurityjwt.security;

import com.example.springsecurityjwt.dto.AuthenticationResponse;
import com.example.springsecurityjwt.dto.UserDetailsDTO;
import com.example.springsecurityjwt.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private JwtUtil jwtUtil;
    private ObjectMapper objectMapper;

    public CustomAuthenticationSuccessHandler(JwtUtil jwtUtil, ObjectMapper objectMapper) {
        this.jwtUtil = jwtUtil;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        UserDetailsDTO userDetailsDTO = (UserDetailsDTO)authentication.getPrincipal();
        AuthenticationResponse authenticationResponse = AuthenticationResponse.builder()
                .token(jwtUtil.generateToken(userDetailsDTO))
                .refreshToken(jwtUtil.generateRefreshToken(userDetailsDTO))
                .build();

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(authenticationResponse));
        response.setStatus(200);
    }
}
