package com.example.springsecurityjwt.authentication.oauth2;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuth2CallbackRequest {
    private String code;
    private String state;

    @Builder
    public OAuth2CallbackRequest(String code, String state) {
        this.code = code;
        this.state = state;
    }
}
