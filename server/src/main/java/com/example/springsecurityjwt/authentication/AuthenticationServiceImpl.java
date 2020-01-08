package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.authentication.oauth2.OAuth2ProcessException;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2Token;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountDTO;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.users.User;
import com.example.springsecurityjwt.users.UserRepository;
import com.example.springsecurityjwt.users.UserType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final OAuth2AccountRepository oAuth2AccountRepository;

    @Override
    public UserDetails authenticateUsernamePassword(String username, String password) {

        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            return (UserDetails) authentication.getPrincipal();
        } catch (AuthenticationException e) {
            throw new AuthenticationProcessException("Username or password is wrong");
        }
    }

    @Override
    @Transactional
    public UserDetails registerOrLoadOAuth2User(String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo) {

        Optional<OAuth2Account> optOAuth2Account = oAuth2AccountRepository.findByProviderAndProviderId(provider, userInfo.getId());
        User user = null;

        //가입된 계정이 존재할때
        if (optOAuth2Account.isPresent()) {
            OAuth2Account oAuth2Account = optOAuth2Account.get();
            user = oAuth2Account.getUser();
            //토큰 업데이트
            oAuth2Account.updateToken(oAuth2Token.getToken(), oAuth2Token.getRefreshToken(), oAuth2Token.getExpiredAt());
        }
        //가입된 계정이 존재하지 않을때
        else {
            //이메일 정보가 있을때
            if (userInfo.getEmail() != null) {
                // 같은 이메일을 사용하는 계정이 존재하는지 확인 후 있다면 소셜 계정과 연결시키고 없다면 새로 생성한다
                user = userRepository.findByEmail(userInfo.getEmail())
                        .orElse(User.builder()
                                .username(provider + "_" + userInfo.getId())
                                .name(userInfo.getName())
                                .email(userInfo.getEmail())
                                .type(UserType.OAUTH)
                                .build());
            }
            //이메일 정보가 없을때
            else {
                user = User.builder()
                        .username(provider + "_" + userInfo.getId())
                        .name(userInfo.getName())
                        .type(UserType.OAUTH)
                        .build();
            }

            //새로 생성된 유저이면 db에 저장
            if(user.getId() == null)
                userRepository.save(user);

            //소셜 계정 정보 생성
            OAuth2Account newAccount = OAuth2Account.builder()
                    .provider(provider)
                    .providerId(userInfo.getId())
                    .user(user)
                    .token(oAuth2Token.getToken())
                    .refreshToken(oAuth2Token.getRefreshToken())
                    .tokenExpiredAt(oAuth2Token.getExpiredAt())
                    .build();

            oAuth2AccountRepository.save(newAccount);
        }

        return CustomUserDetails.builder()
                .id(user.getId())
                .username(user.getUsername())
                .name(user.getName())
                .email(user.getEmail())
                .type(user.getType())
                .authorities(user.getAuthorities()).build();
    }

    @Override
    @Transactional
    public UserDetails linkOAuth2Account(String targetUsername, String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo) {

        //해당 소셜 계정으로 연동된 계정이 존재하는 경우
        if (oAuth2AccountRepository.existsByProviderAndProviderId(provider, userInfo.getId()))
            throw new OAuth2ProcessException("This account is already linked");

        User user = userRepository.findByUsername(targetUsername)
                .orElseThrow(() -> new UsernameNotFoundException("Member not found"));

        //계정과 연동된 소셜 계정이 존재하는 경우
        if(oAuth2AccountRepository.existsByUser(user))
            throw new OAuth2ProcessException("This user has already linked account");

        //소셜 계정 정보 생성
        OAuth2Account oAuth2Account = OAuth2Account.builder()
                .provider(provider)
                .providerId(userInfo.getId())
                .user(user)
                .token(oAuth2Token.getToken())
                .refreshToken(oAuth2Token.getRefreshToken())
                .tokenExpiredAt(oAuth2Token.getExpiredAt())
                .build();

        oAuth2AccountRepository.save(oAuth2Account);

        return CustomUserDetails.builder()
                .id(user.getId())
                .username(user.getUsername())
                .name(user.getName())
                .email(user.getEmail())
                .type(user.getType())
                .authorities(user.getAuthorities()).build();
    }

    @Override
    public OAuth2AccountDTO loadOAuth2Account(String provider, Long userId) {
        OAuth2Account oAuth2Account = oAuth2AccountRepository.findByProviderAndUserId(provider, userId).orElseThrow(() -> new OAuth2ProcessException("Not found this account"));
        return OAuth2AccountDTO.builder()
                .provider(oAuth2Account.getProvider())
                .providerId(oAuth2Account.getProviderId())
                .token(oAuth2Account.getToken())
                .refreshToken(oAuth2Account.getRefreshToken())
                .tokenExpiredAt(oAuth2Account.getTokenExpiredAt())
                .build();
    }

    @Override
    @Transactional
    public void unlinkOAuth2Account(String provider, String providerId, Long userId) {
        OAuth2Account oAuth2Account = oAuth2AccountRepository.findByProviderAndProviderIdAndUserId(provider, providerId, userId).orElseThrow(() -> new OAuth2ProcessException("Account not found"));

        if(oAuth2Account.getUser().getType().equals(UserType.OAUTH))
            throw new OAuth2ProcessException("This account type is OAUTH");

        oAuth2AccountRepository.delete(oAuth2Account);
    }
}
