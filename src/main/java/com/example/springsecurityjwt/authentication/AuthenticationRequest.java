package com.example.springsecurityjwt.authentication;

import com.sun.istack.NotNull;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AuthenticationRequest {
    @NotNull
    private String username;
    @NotNull
    private String password;
    @NotNull
    private String redirectUri;

    public AuthenticationRequest(String username, String password, String redirectUri) {
        this.username = username;
        this.password = password;
        this.redirectUri = redirectUri;
    }
}
