package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.security.AuthorityType;
import com.example.springsecurityjwt.util.DateConvertor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
public class UserProfileResponse {

    private Long id;
    private String name;
    private String email;
    private List<AuthorityType> authorities;
    private String socialProvider;
    private Long linkedAt;

    @Builder
    public UserProfileResponse(Long id, String name, String email, List<AuthorityType> authorities, String socialProvider, LocalDateTime linkedAt) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.authorities = authorities;
        this.socialProvider = socialProvider;
        if (linkedAt != null)
            this.linkedAt = DateConvertor.toEpochMilli(linkedAt);
    }
}
