package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.BaseEntity;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Table(name="TBL_AUTHORIZATION_CODE")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuthorizationCode extends BaseEntity {

    private String code;
    private String username;

    @Builder
    public AuthorizationCode(String code, String username) {
        this.code = code;
        this.username = username;
    }
}
