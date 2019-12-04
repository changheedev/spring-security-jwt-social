package com.example.springsecurityjwt.controller;

import com.example.springsecurityjwt.dto.AuthenticationRequest;
import com.example.springsecurityjwt.dto.AuthenticationResponse;
import com.example.springsecurityjwt.dto.UserDetailsDTO;
import com.example.springsecurityjwt.security.CustomUserDetailsService;
import com.example.springsecurityjwt.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class AuthenticationController {

    private final CustomUserDetailsService customUserDetailsService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public AuthenticationController(CustomUserDetailsService customUserDetailsService, AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.customUserDetailsService = customUserDetailsService;
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {

        try {

            log.debug(authenticationRequest.getUsername());
            log.debug(authenticationRequest.getPassword());

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        } catch (UsernameNotFoundException e) {
            throw new UsernameNotFoundException("이메일 또는 비밀번호가 틀렸습니다.");
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("이메일 또는 비밀번호가 틀렸습니다.");
        }

        final UserDetails userDetails = customUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        final AuthenticationResponse authenticationResponse = AuthenticationResponse.builder()
                .token(jwtUtil.generateToken((UserDetailsDTO) userDetails))
                .refreshToken(jwtUtil.generateRefreshToken((UserDetailsDTO) userDetails))
                .build();

        return ResponseEntity.ok(authenticationResponse);
    }

}
