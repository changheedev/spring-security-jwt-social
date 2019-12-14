package com.example.springsecurityjwt.oauth;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuth2AuthorizationRequestParams {
    private String redirectUri;
    private String requestType;
    private String linkUsername;

    @Builder
    public OAuth2AuthorizationRequestParams(String redirectUri, String requestType, String linkUsername) {
        this.redirectUri = redirectUri;
        this.requestType = requestType;
        this.linkUsername = linkUsername;
    }
}
