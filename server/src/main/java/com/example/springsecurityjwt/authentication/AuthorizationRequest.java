package com.example.springsecurityjwt.authentication;

import com.sun.istack.NotNull;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthorizationRequest {
    @NotNull
    private String username;
    @NotNull
    private String password;
    private String redirectUri;
    private String responseType;

    @Builder
    public AuthorizationRequest(String username, String password, String redirectUri, String responseType) {
        this.username = username;
        this.password = password;
        this.redirectUri = (redirectUri == null) ? "/" : redirectUri;
        this.responseType = (responseType == null) ? "response_body" : responseType;
    }
}
