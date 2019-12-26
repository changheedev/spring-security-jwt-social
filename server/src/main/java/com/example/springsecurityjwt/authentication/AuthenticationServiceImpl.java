package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.jwt.JWT;
import com.example.springsecurityjwt.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
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
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProvider jwtProvider;

    @Override
    public UserDetails authenticateUsernamePassword(String username, String password) {

        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            return (UserDetails) authentication.getPrincipal();
        } catch (UsernameNotFoundException e) {
            throw new UsernameNotFoundException("이메일 또는 비밀번호가 틀렸습니다.");
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("이메일 또는 비밀번호가 틀렸습니다.");
        }
    }

    @Override
    @Transactional
    public JWT issueToken(String username) {
        JWT token = JWT.builder()
                .token(jwtProvider.generateToken(username))
                .refreshToken(jwtProvider.generateRefreshToken())
                .build();

        //리프레쉬 토큰 새로 저장
        storeRefreshToken(username, token.getRefreshToken());
        return token;
    }

    @Override
    @Transactional
    public JWT refreshAccessToken(String oldToken, String refreshToken) {

        String username = jwtProvider.extractUsername(oldToken);
        RefreshToken refreshTokenObj = refreshTokenRepository.findByUsernameAndRefreshToken(username, refreshToken)
                .orElseThrow(() -> new AuthenticationFailedException("사용할 수 없는 Refresh Token 입니다."));

        if (refreshTokenObj.isExpired())
            throw new AuthenticationFailedException("사용할 수 없는 Refresh Token 입니다.");

        JWT token = JWT.builder()
                .token(jwtProvider.generateToken(username)).build();

        log.debug(refreshTokenObj.getExpiredAt().toString());

        //refresh 토큰이 만료 한달전이면 새로 발급
        if (refreshTokenObj.getExpiredAt().isBefore(LocalDateTime.now().plusMonths(1))) {
            //리프레쉬 토큰 업데이트
            String newRefreshToken = jwtProvider.generateRefreshToken();
            storeRefreshToken(username, newRefreshToken);
            token.setRefreshToken(newRefreshToken);
        }
        //기존 refresh 토큰 재사용
        else token.setRefreshToken(refreshToken);

        return token;
    }

    @Override
    @Transactional
    public void expiredRefreshToken(String username) {

        Optional<RefreshToken> optRefreshToken = refreshTokenRepository.findByUsername(username);
        //해당 username 으로 저장된 리프레쉬 토큰이 없는 경우 리턴
        if (!optRefreshToken.isPresent()) return;
        refreshTokenRepository.delete(optRefreshToken.get());
    }

    //refresh token db 저장
    private void storeRefreshToken(String username, String refreshToken) {
        if (refreshTokenRepository.existsByUsername(username)) {
            refreshTokenRepository.deleteByUsername(username);
        }
        refreshTokenRepository.save(RefreshToken.builder()
                .username(username)
                .refreshToken(refreshToken)
                .expiredAt(LocalDateTime.now().plusSeconds(jwtProvider.getProperties().getRefreshTokenExpired()))
                .build());
    }
}
