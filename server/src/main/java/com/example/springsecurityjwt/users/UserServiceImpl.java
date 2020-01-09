package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.authentication.UnauthorizedException;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2ProcessException;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2Token;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountDTO;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final OAuth2AccountRepository oAuth2AccountRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void signUpService(SignUpRequest signUpRequest) {

        if (userRepository.findByUsername(signUpRequest.getEmail()).isPresent())
            throw new DuplicatedUsernameException("This is a registered member");

        User user = User.builder()
                .username(signUpRequest.getEmail())
                .name(signUpRequest.getName())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .type(UserType.DEFAULT)
                .build();

        userRepository.save(user);
    }

    @Override
    public Optional<OAuth2AccountDTO> getOAuth2Account(String username) {
        Optional<User> optionalUser = userRepository.findByUsername(username);
        if(!optionalUser.isPresent() || optionalUser.get().getSocial() == null) return Optional.empty();
        return Optional.of(optionalUser.get().getSocial().toDTO());
    }

    @Override
    @Transactional
    public void updateProfile(String username, UpdateProfileRequest updateProfileRequest) {

        User user = userRepository.findByUsername(username).get();

        //이름이 변경되었는지 체크
        if (!user.getName().equals(updateProfileRequest.getName()))
            user.updateName(updateProfileRequest.getName());

        //이메일이 변경되었는지 체크
        if (!user.getEmail().equals(updateProfileRequest.getEmail())) {
            if (userRepository.existsByEmail(updateProfileRequest.getEmail()))
                throw new DuplicatedUsernameException("This email is already in use");
            user.updateEmail(updateProfileRequest.getEmail());
        }
    }


    @Override
    @Transactional
    public UserDetails loginOAuth2User(String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo) {

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
            //소셜 계정 정보 생성
            OAuth2Account newAccount = OAuth2Account.builder()
                    .provider(provider)
                    .providerId(userInfo.getId())
                    .token(oAuth2Token.getToken())
                    .refreshToken(oAuth2Token.getRefreshToken())
                    .tokenExpiredAt(oAuth2Token.getExpiredAt()).build();
            oAuth2AccountRepository.save(newAccount);

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
            if (user.getId() == null)
                userRepository.save(user);

            //연관관계 설정
            user.linkSocial(newAccount);
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

        //소셜 계정과 연동된 다른 계정이 존재하는지 검사
        if (oAuth2AccountRepository.existsByProviderAndProviderId(provider, userInfo.getId()))
            throw new OAuth2ProcessException("This account is already linked");

        User user = userRepository.findByUsername(targetUsername)
                .orElseThrow(() -> new UsernameNotFoundException("Member not found"));

        //계정과 연동된 소셜 계정이 존재하는지 검사
        if(user.getSocial() != null)
            throw new OAuth2ProcessException("This user has already linked account");

        //소셜 계정 정보 생성
        OAuth2Account oAuth2Account = OAuth2Account.builder()
                .provider(provider)
                .providerId(userInfo.getId())
                .token(oAuth2Token.getToken())
                .refreshToken(oAuth2Token.getRefreshToken())
                .tokenExpiredAt(oAuth2Token.getExpiredAt())
                .build();
        oAuth2AccountRepository.save(oAuth2Account);

        //연관관계 설정
        user.linkSocial(oAuth2Account);

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
    public void unlinkOAuth2Account(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UnauthorizedException("username cannot be null"));

        if(user.getType().equals(UserType.OAUTH) || user.getSocial() == null)
            throw new RuntimeException("소셜 서비스로 가입된 계정이거나 연동된 정보가 없습니다");

        //연관관계 해제
        OAuth2Account oAuth2Account = user.getSocial();
        user.unlinkSocial();
        oAuth2AccountRepository.delete(oAuth2Account);
    }

    @Override
    @Transactional
    public void withdrawUser(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UnauthorizedException("username cannot be null"));
        userRepository.delete(user);
    }
}
