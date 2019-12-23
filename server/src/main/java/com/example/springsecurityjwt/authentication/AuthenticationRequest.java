package com.example.springsecurityjwt.authentication;

import com.sun.istack.NotNull;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthenticationRequest {
    @NotNull
    private String username;
    @NotNull
    private String password;
    private String responseType;

    @Builder
    public AuthenticationRequest(String username, String password, String responseType) {
        this.username = username;
        this.password = password;
        this.responseType = (responseType == null) ? "response_body" : responseType;
    }
}
