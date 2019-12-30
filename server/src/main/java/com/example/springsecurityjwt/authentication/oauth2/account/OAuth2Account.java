package com.example.springsecurityjwt.authentication.oauth2.account;

import com.example.springsecurityjwt.BaseEntity;
import com.example.springsecurityjwt.users.User;
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

    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "USER_ID")
    private User user;
    private String providerId;
    private String provider;

    @Builder
    public OAuth2Account(User user, String providerId, String provider) {
        this.user = user;
        this.providerId = providerId;
        this.provider = provider;
    }
}
