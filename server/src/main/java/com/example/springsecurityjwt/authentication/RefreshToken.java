package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.BaseEntity;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import java.time.LocalDateTime;

@Getter
@Entity
@Table(name = "TBL_REFRESH_TOKEN")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken extends BaseEntity {

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String refreshToken;

    @Column(nullable = false)
    private LocalDateTime expiredAt;

    @Builder
    public RefreshToken(String username, String refreshToken, LocalDateTime expiredAt) {
        this.username = username;
        this.refreshToken = refreshToken;
        this.expiredAt = expiredAt;
    }

    public boolean isExpired() {
        if(expiredAt.isBefore(LocalDateTime.now())) return true;
        return false;
    }
}
