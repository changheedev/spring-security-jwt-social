package com.example.springsecurityjwt.authentication.oauth2.service;

import com.example.springsecurityjwt.authentication.oauth2.ClientRegistration;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2RequestFailedException;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2Token;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

public class KakaoOAuth2Service extends OAuth2Service{
    public KakaoOAuth2Service(RestTemplate restTemplate) {
        super(restTemplate);
    }

    @Override
    public void unlink(ClientRegistration clientRegistration, OAuth2Token token){

        //토큰이 만료되었다면 토큰을 갱신
        token = refreshOAuth2Token(clientRegistration, token);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token.getToken());

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(headers);

        ResponseEntity<String> entity = null;
        try {
            entity = restTemplate.exchange(clientRegistration.getProviderDetails().getUnlinkUri(), HttpMethod.POST, httpEntity, String.class);
        } catch (HttpStatusCodeException exception) {
            int statusCode = exception.getStatusCode().value();
            throw new OAuth2RequestFailedException(String.format("%s 연동해제 실패. [응답코드 : %d].", clientRegistration.getRegistrationId().toUpperCase(), statusCode), exception);
        }
    }
}

