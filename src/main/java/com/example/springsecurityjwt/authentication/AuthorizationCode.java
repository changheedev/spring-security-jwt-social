package com.example.springsecurityjwt.authentication;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Table(name="TBL_AUTHORIZATION_CODE")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuthorizationCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String code;
    private String username;

    @Builder
    public AuthorizationCode(String code, String username) {
        this.code = code;
        this.username = username;
    }
}
