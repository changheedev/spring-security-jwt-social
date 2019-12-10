package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.security.CustomUserDetailsService;
import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.security.CustomUserDetails;
import io.jsonwebtoken.JwtException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Optional;
import java.util.UUID;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtProvider jwtProvider;

    public AuthenticationServiceImpl(AuthorizationCodeRepository authorizationCodeRepository, AuthenticationManager authenticationManager, CustomUserDetailsService customUserDetailsService, JwtProvider jwtProvider) {
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.authenticationManager = authenticationManager;
        this.customUserDetailsService = customUserDetailsService;
        this.jwtProvider = jwtProvider;
    }

    @Transactional
    public String generateAuthorizationCode(String username, String password, String redirectUrl) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (UsernameNotFoundException e) {
            throw new UsernameNotFoundException("이메일 또는 비밀번호가 틀렸습니다.");
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("이메일 또는 비밀번호가 틀렸습니다.");
        }

        String code = UUID.randomUUID().toString().replaceAll("-", "");
        AuthorizationCode authorizationCode = AuthorizationCode.builder().code(code).username(username).build();
        authorizationCodeRepository.save(authorizationCode);

        return UriComponentsBuilder.fromUriString(redirectUrl)
                .queryParam("code", code)
                .build().toUriString();
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
