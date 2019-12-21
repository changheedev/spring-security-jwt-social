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
    @NotNull
    private String redirectUri;

    @Builder
    public AuthenticationRequest(String username, String password) {
        this.username = username;
        this.password = password;
        this.redirectUri = redirectUri;
    }
}
