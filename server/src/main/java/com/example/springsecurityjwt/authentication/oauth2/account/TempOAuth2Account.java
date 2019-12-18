package com.example.springsecurityjwt.authentication.oauth2.account;

import com.example.springsecurityjwt.BaseEntity;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "TBL_TEMP_OAUTH_ACCOUNT")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class TempOAuth2Account extends BaseEntity {

    private String providerId;
    private String provider;
    private String name;

    @Builder
    public TempOAuth2Account(String providerId, String provider, String name) {
        this.providerId = providerId;
        this.provider = provider;
        this.name = name;
    }
}