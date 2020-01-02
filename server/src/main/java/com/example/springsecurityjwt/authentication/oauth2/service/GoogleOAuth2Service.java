package com.example.springsecurityjwt.authentication.oauth2.service;

import com.example.springsecurityjwt.authentication.oauth2.ClientRegistration;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2ProcessException;
import org.springframework.http.*;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

public class GoogleOAuth2Service extends OAuth2Service{
    public GoogleOAuth2Service(RestTemplate restTemplate) {
        super(restTemplate);
    }

    @Override
    public void unlink(ClientRegistration clientRegistration, String accessToken){

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(headers);

        String unlinkUri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getUnlinkUri())
                .queryParam("token", accessToken).encode().build().toUriString();


        ResponseEntity<String> entity = null;
        try {
            entity = restTemplate.exchange(unlinkUri, HttpMethod.GET, httpEntity, String.class);
        } catch (HttpStatusCodeException exception) {
            int statusCode = exception.getStatusCode().value();
            throw new OAuth2ProcessException(String.format("Unlink failed [%d].", statusCode), exception);
        }
    }
}
