package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.security.CustomUserDetailsService;
import io.jsonwebtoken.JwtException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtProvider jwtProvider;

    public AuthenticationServiceImpl(AuthorizationCodeRepository authorizationCodeRepository, CustomUserDetailsService customUserDetailsService, JwtProvider jwtProvider) {
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.customUserDetailsService = customUserDetailsService;
        this.jwtProvider = jwtProvider;
    }

    @Transactional
    public String generateAuthorizationCode(String username) {
        String code = UUID.randomUUID().toString().replaceAll("-", "");
        AuthorizationCode authorizationCode = AuthorizationCode.builder().code(code).username(username).build();
        authorizationCodeRepository.save(authorizationCode);
        return code;
    }

    @Transactional
    public AccessTokenResponse exchangeAuthorizationCodeToAccessToken(String code, String username) {

        AuthorizationCode authorizationCode = authorizationCodeRepository.findByCodeAndUsername(code, username)
                .orElseThrow(() -> new AccessTokenGenerateException("잘못된 코드가 사용되었습니다."));

        CustomUserDetails userDetails = (CustomUserDetails) customUserDetailsService.loadUserByUsername(username);
        AccessTokenResponse accessTokenResponse = generateAccessToken(userDetails);

        authorizationCodeRepository.delete(authorizationCode);
        return accessTokenResponse;
    }

    /* 손봐야함 */
    @Transactional
    public AccessTokenResponse refreshAuthenticationToken(String refreshToken, String username) {

        String tokenUsername = jwtProvider.extractUsername(refreshToken);
        if (tokenUsername == null) throw new UsernameNotFoundException("찾을 수 없는 회원입니다.");

        CustomUserDetails userDetails = (CustomUserDetails) customUserDetailsService.loadUserByUsername(username);
        if (!jwtProvider.validateToken(refreshToken, userDetails))
            throw new JwtException("유효하지 않은 토큰입니다.");

        AccessTokenResponse accessTokenResponse = AccessTokenResponse.builder()
                .token(jwtProvider.generateToken(userDetails))
                .refreshToken(jwtProvider.generateRefreshToken(userDetails))
                .build();

        return accessTokenResponse;
    }

    private AccessTokenResponse generateAccessToken(CustomUserDetails userDetails) {
        return AccessTokenResponse.builder()
                .token(jwtProvider.generateToken(userDetails))
                .refreshToken(jwtProvider.generateRefreshToken(userDetails))
                .build();
    }
}
