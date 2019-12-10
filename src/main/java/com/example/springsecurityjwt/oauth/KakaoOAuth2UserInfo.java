package com.example.springsecurityjwt.oauth;

import java.util.Map;

public class KakaoOAuth2UserInfo extends OAuth2UserInfo {

    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return String.valueOf(attributes.get("id"));
    }

    @Override
    public String getName() {
        return (String) parsingProperties().get("nickname");
    }

    @Override
    public String getEmail() {
        return (String) parsingAccount().get("email");
    }

    private Map<String, Object> parsingProperties() {
        return (Map<String, Object>) attributes.get("properties");
    }

    private Map<String, Object> parsingAccount() {
        return (Map<String, Object>) attributes.get("kakao_account");
    }
}
