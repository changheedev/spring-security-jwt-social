package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.security.CustomUserDetailsService;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService customUserDetailsService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProvider jwtProvider;

    @Override
    public UserDetails authenticateUsernamePassword(String username, String password) {

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
            return userDetails;
        } catch (UsernameNotFoundException e) {
            throw new UsernameNotFoundException("이메일 또는 비밀번호가 틀렸습니다.");
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("이메일 또는 비밀번호가 틀렸습니다.");
        }
    }

    @Override
    @Transactional
    public AccessTokenResponse issueAccessToken(UserDetails userDetails) {
        AccessTokenResponse accessTokenResponse = AccessTokenResponse.builder()
                .token(jwtProvider.generateToken((CustomUserDetails)userDetails))
                .refreshToken(jwtProvider.generateRefreshToken((CustomUserDetails)userDetails))
                .build();

        //리프레쉬 토큰 새로 저장
        storeRefreshToken(userDetails, accessTokenResponse.getRefreshToken());

        return accessTokenResponse;
    }

    @Override
    @Transactional
    public AccessTokenResponse refreshAuthenticationToken(String refreshToken, String username) {

        String tokenUsername = jwtProvider.extractUsername(refreshToken);
        //토큰에서 username 을 추출할 수 없는 경우
        if (tokenUsername == null) throw new AuthenticationFailedException("사용할 수 없는 Refresh Token 입니다.");

        Optional<RefreshToken> optRefreshToken = refreshTokenRepository.findByUsername(tokenUsername);

        //refresh token 엔티티를 찾을 수 없거나 요청된 refresh token 과 다른 경우
        if(!optRefreshToken.isPresent() || !optRefreshToken.get().getRefreshToken().equals(refreshToken))
            throw new AuthenticationFailedException("사용할 수 없는 Refresh Token 입니다.");

        CustomUserDetails userDetails = (CustomUserDetails) customUserDetailsService.loadUserByUsername(username);
        if (!jwtProvider.validateToken(refreshToken, userDetails))
            throw new AuthenticationFailedException("사용할 수 없는 Refresh Token 입니다.");

        AccessTokenResponse accessTokenResponse = null;

        //refresh 토큰이 만료 한달전이면 새로 발급
        if(jwtProvider.extractExpiration(refreshToken).isBefore(LocalDateTime.now().plusMonths(1))) {
            accessTokenResponse = AccessTokenResponse.builder()
                    .token(jwtProvider.generateToken(userDetails))
                    .refreshToken(jwtProvider.generateRefreshToken(userDetails))
                    .build();

            //리프레쉬 토큰 새로 저장
            storeRefreshToken(userDetails, accessTokenResponse.getRefreshToken());
        }
        //기존 토큰 재사용
        else {
            accessTokenResponse = AccessTokenResponse.builder()
                    .token(jwtProvider.generateToken(userDetails))
                    .refreshToken(refreshToken)
                    .build();
        }

        return accessTokenResponse;
    }

    @Override
    @Transactional
    public void expiredRefreshToken(String username) {

        Optional<RefreshToken> optRefreshToken = refreshTokenRepository.findByUsername(username);

        //refresh token 엔티티를 찾을 수 없는 경우
        if(!optRefreshToken.isPresent())
            throw new AuthenticationFailedException("사용할 수 없는 Refresh Token 입니다.");

        refreshTokenRepository.delete(optRefreshToken.get());
    }

    //refresh token db 저장
    private void storeRefreshToken(UserDetails userDetails, String refreshToken){
        if(refreshTokenRepository.existsByUsername(userDetails.getUsername())){
            refreshTokenRepository.deleteByUsername(userDetails.getUsername());
        }
        refreshTokenRepository.save(RefreshToken.builder().username(userDetails.getUsername()).refreshToken(refreshToken).build());
    }
}
