package com.example.springsecurityjwt.authentication.oauth2.service;

import com.example.springsecurityjwt.authentication.oauth2.ClientRegistration;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2ProcessException;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URLEncoder;

public class NaverOAuth2Service extends OAuth2Service{

    public NaverOAuth2Service(RestTemplate restTemplate) {
        super(restTemplate);
    }

    @Override
    public void unlink(ClientRegistration clientRegistration, String accessToken){
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        try {
            params.add("client_id", clientRegistration.getClientId());
            params.add("client_secret", clientRegistration.getClientSecret());
            params.add("grant_type", "delete");
            params.add("service_provider", "NAVER");
            params.add("access_token", URLEncoder.encode(accessToken, "utf-8"));
        }
        catch(IOException e) {
            throw new OAuth2ProcessException("Encode access token failed");
        }

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(params, headers);

        ResponseEntity<String> entity = null;
        try {
            entity = restTemplate.exchange(clientRegistration.getProviderDetails().getUnlinkUri(), HttpMethod.POST, httpEntity, String.class);
        } catch (HttpStatusCodeException exception) {
            int statusCode = exception.getStatusCode().value();
            throw new OAuth2ProcessException(String.format("Unlink failed [%d].", statusCode), exception);
        }
    }
}

