package com.example.springsecurityjwt.oauth;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Table(name = "TBL_OAUTH_ACCOUNT")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OAuthAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;

    private String providerId;

    @Enumerated(value = EnumType.STRING)
    private OAuthProvider provider;

    @Builder
    public OAuthAccount(Long userId, String providerId, OAuthProvider provider) {
        this.userId = userId;
        this.providerId = providerId;
        this.provider = provider;
    }
}
