package com.example.springsecurityjwt.oauth2;

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
    private String provider;

    @Builder
    public OAuth2Account(Long userId, String providerId, String provider) {
        this.userId = userId;
        this.providerId = providerId;
        this.provider = provider;
    }
}
