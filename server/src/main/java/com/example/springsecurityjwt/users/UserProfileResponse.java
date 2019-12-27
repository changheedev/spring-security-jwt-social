package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.security.AuthorityType;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class UserProfileResponse {

    private Long id;
    private String name;
    private String email;
    private List<AuthorityType> authorities;

    @Builder
    public UserProfileResponse(Long id, String name, String email, List<AuthorityType> authorities) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.authorities = authorities;
    }
}
