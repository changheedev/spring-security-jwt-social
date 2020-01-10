package com.example.springsecurityjwt.users;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Email;
import javax.validation.constraints.Size;

@Getter
@Setter
public class UpdateProfileRequest {
    @Size(min = 1, max = 20, message = "이름이 입력되지 않았거나 너무 긴 이름입니다.")
    private String name;
    @Email(message = "이메일 형식이 잘못되었습니다.")
    private String email;

    @Builder
    public UpdateProfileRequest(String name, String email) {
        this.name = name;
        this.email = email;
    }
}
