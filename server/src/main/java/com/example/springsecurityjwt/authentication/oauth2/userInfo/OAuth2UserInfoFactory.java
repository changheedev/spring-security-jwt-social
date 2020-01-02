package com.example.springsecurityjwt.authentication.oauth2.userInfo;

import com.example.springsecurityjwt.authentication.oauth2.OAuth2ProcessException;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase("google")) {
            return new GoogleOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase("kakao")) {
            return new KakaoOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase("naver")) {
            return new NaverOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2ProcessException(registrationId + " 로그인은 현재 지원하지 않습니다.");
        }
    }
}