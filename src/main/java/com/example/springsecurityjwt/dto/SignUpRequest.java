package com.example.springsecurityjwt.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class SignUpRequest {
    private String name;
    private String email;
    private String password;
}
