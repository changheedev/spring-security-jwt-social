package com.example.springsecurityjwt.authentication;

        import lombok.Builder;
        import lombok.Getter;
        import lombok.Setter;
        import org.springframework.security.oauth2.core.AuthorizationGrantType;

@Getter
@Setter
public class AuthorizationRequest {

    private AuthorizationGrantType grantType;
    private String username;
    private String code;
    private String refreshToken;

    @Builder
    public AuthorizationRequest(AuthorizationGrantType grantType, String username, String code, String refreshToken) {
        this.grantType = grantType;
        this.username = username;
        this.code = code;
        this.refreshToken = refreshToken;
    }
}
