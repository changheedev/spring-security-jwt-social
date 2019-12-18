package com.example.springsecurityjwt.authentication.oauth2;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuth2CallbackResponse {
    private String status;
    private Object data;

    @Builder
    public OAuth2CallbackResponse(String status, Object data) {
        this.status = status;
        this.data = data;
    }
}
