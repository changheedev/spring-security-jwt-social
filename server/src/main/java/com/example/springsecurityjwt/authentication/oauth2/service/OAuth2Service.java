package com.example.springsecurityjwt.authentication.oauth2.service;

import com.example.springsecurityjwt.authentication.oauth2.ClientRegistration;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2RequestFailedException;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2Token;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfoFactory;
import com.example.springsecurityjwt.util.JsonUtils;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Map;

public abstract class OAuth2Service {

    protected final Logger log = LoggerFactory.getLogger(this.getClass());
    protected final RestTemplate restTemplate;

    public OAuth2Service(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void redirectAuthorizePage(ClientRegistration clientRegistration, String state, HttpServletResponse response) throws IOException {
        String authorizationUri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getAuthorizationUri())
                .queryParam("client_id", clientRegistration.getClientId())
                .queryParam("response_type", "code")
                .queryParam("access_type", "offline") //refresh token 을 받기 위한 옵션 : for google
                .queryParam("include_granted_scopes", true) // for google
                .queryParam("scope", String.join("+", clientRegistration.getScopes()))
                .queryParam("state", state)
                .queryParam("redirect_uri", clientRegistration.getRedirectUri())
                .build().encode(StandardCharsets.UTF_8).toUriString();
        response.sendRedirect(authorizationUri);
    }

    public OAuth2Token getAccessToken(ClientRegistration clientRegistration, String code, String state) {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", clientRegistration.getClientId());
        params.add("client_secret", clientRegistration.getClientSecret());
        params.add("grant_type", clientRegistration.getAuthorizationGrantType());
        params.add("code", code);
        params.add("state", state);
        params.add("redirect_uri", clientRegistration.getRedirectUri());

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(params, headers);

        ResponseEntity<String> entity = null;
        try {
            entity = restTemplate.exchange(clientRegistration.getProviderDetails().getTokenUri(), HttpMethod.POST, httpEntity, String.class);
        } catch (HttpStatusCodeException exception) {
            int statusCode = exception.getStatusCode().value();
            throw new OAuth2RequestFailedException(String.format("%s 토큰 요청 실패 [응답코드 : %d].", clientRegistration.getRegistrationId().toUpperCase(), statusCode), exception);
        }

        log.debug(entity.getBody());
        JsonObject jsonObj = JsonUtils.parse(entity.getBody()).getAsJsonObject();
        String accessToken = jsonObj.get("access_token").getAsString();
        String refreshToken = jsonObj.get("refresh_token").getAsString();
        LocalDateTime expiredAt = LocalDateTime.now().plusSeconds(jsonObj.get("expires_in").getAsLong());

        return new OAuth2Token(accessToken, refreshToken, expiredAt);
    }

    protected OAuth2Token refreshOAuth2Token(ClientRegistration clientRegistration, OAuth2Token token) {

        //토큰이 만료되지 않았다면 원래 토큰을 리턴
        if (LocalDateTime.now().isBefore(token.getExpiredAt())) return token;

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", clientRegistration.getClientId());
        params.add("client_secret", clientRegistration.getClientSecret());
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", token.getRefreshToken());

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(params, headers);

        ResponseEntity<String> entity = null;
        try {
            entity = restTemplate.exchange(clientRegistration.getProviderDetails().getTokenUri(), HttpMethod.POST, httpEntity, String.class);
        } catch (HttpStatusCodeException exception) {
            int statusCode = exception.getStatusCode().value();
            throw new OAuth2RequestFailedException(String.format("%s 토큰 갱신 실패 [응답코드 : %d].", clientRegistration.getRegistrationId().toUpperCase(), statusCode), exception);
        }

        JsonObject jsonObj = JsonUtils.parse(entity.getBody()).getAsJsonObject();
        String accessToken = jsonObj.get("access_token").getAsString();
        //naver의 경우는 null
        String newRefreshToken = jsonObj.get("refresh_token").getAsString();
        LocalDateTime expiredAt = LocalDateTime.now().plusSeconds(jsonObj.get("expires_in").getAsLong());

        return new OAuth2Token(accessToken, newRefreshToken != null ? newRefreshToken : token.getRefreshToken(), expiredAt);
    }

    public OAuth2UserInfo getUserInfo(ClientRegistration clientRegistration, String accessToken) {

        HttpHeaders headers = new HttpHeaders();

        headers.add("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<?> httpEntity = new HttpEntity<>(headers);

        ResponseEntity<String> entity = null;
        try {
            entity = restTemplate.exchange(clientRegistration.getProviderDetails().getUserInfoUri(), HttpMethod.GET, httpEntity, String.class);
        } catch (HttpStatusCodeException exception) {
            int statusCode = exception.getStatusCode().value();
            throw new OAuth2RequestFailedException(String.format("%s 유저 정보 요청 실패 [응답코드 : %d].", clientRegistration.getRegistrationId().toUpperCase(), statusCode), exception);
        }

        Map<String, Object> userAttributes = JsonUtils.fromJson(entity.getBody(), Map.class);

        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(clientRegistration.getRegistrationId(), userAttributes);

        return userInfo;
    }

    public abstract void unlink(ClientRegistration clientRegistration, OAuth2Token token);
}
