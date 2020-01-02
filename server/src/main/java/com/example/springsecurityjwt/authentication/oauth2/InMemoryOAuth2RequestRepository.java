package com.example.springsecurityjwt.authentication.oauth2;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class InMemoryOAuth2RequestRepository {
    private Map<String, OAuth2AuthorizationRequest> oAuth2RequestMap = new HashMap<>();

    public void saveOAuth2Request(String state, OAuth2AuthorizationRequest oAuth2AuthorizationRequest){
        oAuth2RequestMap.put(state, oAuth2AuthorizationRequest);
    }

    public OAuth2AuthorizationRequest getOAuth2Request(String state){
        return oAuth2RequestMap.get(state);
    }

    public OAuth2AuthorizationRequest deleteOAuth2Request(String state){
        return oAuth2RequestMap.remove(state);
    }
}
