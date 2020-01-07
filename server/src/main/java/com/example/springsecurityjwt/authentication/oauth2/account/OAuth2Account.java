package com.example.springsecurityjwt.authentication.oauth2.account;

import com.example.springsecurityjwt.entity.BaseEntity;
import com.example.springsecurityjwt.users.User;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "TBL_OAUTH_ACCOUNT")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OAuth2Account extends BaseEntity {

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_ID")
    private User user;
    private String providerId;
    private String provider;
    private String token;
    private String refreshToken;
    private LocalDateTime tokenExpiredAt;

    @Builder
    public OAuth2Account(User user, String providerId, String provider, String token, String refreshToken, LocalDateTime tokenExpiredAt) {
        this.user = user;
        this.providerId = providerId;
        this.provider = provider;
        this.token = token;
        this.refreshToken = refreshToken;
        this.tokenExpiredAt = tokenExpiredAt;
    }

    public void updateToken(String token, String refreshToken, LocalDateTime tokenExpiredAt) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.tokenExpiredAt = tokenExpiredAt;
    }
}
