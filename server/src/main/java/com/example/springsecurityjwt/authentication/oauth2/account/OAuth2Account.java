package com.example.springsecurityjwt.authentication.oauth2.account;

import com.example.springsecurityjwt.entity.BaseEntity;
import com.example.springsecurityjwt.users.User;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.util.Assert;

import javax.persistence.Entity;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "TBL_OAUTH_ACCOUNT", uniqueConstraints = {@UniqueConstraint(columnNames = {"provider", "providerId"})})
public class OAuth2Account extends BaseEntity {
    private String providerId;
    private String provider;
    private String token;
    private String refreshToken;
    private LocalDateTime tokenExpiredAt;
    @OneToOne(mappedBy = "social")
    private User user;

    @Builder
    public OAuth2Account(String providerId, String provider, String token, String refreshToken, LocalDateTime tokenExpiredAt) {
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

    public void linkUser(User user) {
        Assert.state(this.user == null, "소셜 계정에 연동 된 다른 계정이 존재합니다.");
        this.user = user;
    }

    public void unlinkUser() {
        Assert.state(this.user != null, "연동 된 계정이 존재하지 않습니다.");
        this.user = null;
    }

    public OAuth2AccountDTO toDTO() {
        return OAuth2AccountDTO.builder()
                .provider(provider)
                .providerId(providerId)
                .createAt(getCreateAt())
                .token(token)
                .refreshToken(refreshToken)
                .tokenExpiredAt(tokenExpiredAt).build();
    }
}
