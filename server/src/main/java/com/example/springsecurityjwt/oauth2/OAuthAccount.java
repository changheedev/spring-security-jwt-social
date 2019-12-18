package com.example.springsecurityjwt.oauth;

import com.example.springsecurityjwt.BaseEntity;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Table(name = "TBL_OAUTH_ACCOUNT")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OAuth2Account extends BaseEntity {

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
