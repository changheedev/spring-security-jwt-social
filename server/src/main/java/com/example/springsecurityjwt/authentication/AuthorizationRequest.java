package com.example.springsecurityjwt.authentication;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;

@Getter
@Setter
public class AuthorizationRequest {
    @NotBlank(message = "이메일을 입력하세요.")
    private String username;
    @NotBlank(message = "패스워드를 입력하세요.")
    private String password;

    @Builder
    public AuthorizationRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }
}
