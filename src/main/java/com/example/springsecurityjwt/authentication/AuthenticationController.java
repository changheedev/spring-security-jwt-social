package com.example.springsecurityjwt.authentication;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;

@RestController
@Slf4j
public class AuthenticationController{

   private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/authenticate")
    public void createAuthorizationCode(@RequestBody AuthenticationRequest authenticationRequest, HttpServletResponse response) throws Exception {
        String targetUrl = authenticationService.generateAuthorizationCode(authenticationRequest.getUsername(), authenticationRequest.getPassword(), authenticationRequest.getRedirectUri());
        response.sendRedirect(targetUrl);
    }

    @PostMapping("/oauth2/token")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthorizationRequest authorizationRequest) throws Exception {

        AccessTokenResponse accessTokenResponse = null;

        if (authorizationRequest.getGrantType().equals(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            accessTokenResponse = authenticationService.exchangeAuthorizationCodeToAccessToken(authorizationRequest.getCode(), authorizationRequest.getUsername());
        } else if (authorizationRequest.getGrantType().equals(AuthorizationGrantType.REFRESH_TOKEN)) {
            accessTokenResponse = authenticationService.refreshAuthenticationToken(authorizationRequest.getRefreshToken(), authorizationRequest.getUsername());
        }

        return ResponseEntity.ok(accessTokenResponse);
    }
}
