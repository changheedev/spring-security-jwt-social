package com.example.springsecurityjwt.users;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateProfileRequest {
    private String name;
    private String email;

    @Builder
    public UpdateProfileRequest(String name, String email) {
        this.name = name;
        this.email = email;
    }
}
