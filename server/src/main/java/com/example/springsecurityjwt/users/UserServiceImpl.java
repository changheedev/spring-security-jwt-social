package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.authentication.oauth2.OAuth2Token;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountDTO;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.validation.SimpleFieldError;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final OAuth2AccountRepository oAuth2AccountRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void signUpService(SignUpRequest signUpRequest){
        checkDuplicateEmail(signUpRequest.getEmail());
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
    @Transactional(readOnly = true)
    public Optional<OAuth2AccountDTO> getOAuth2Account(String username) {
        Optional<User> optionalUser = userRepository.findByUsername(username);
        if (!optionalUser.isPresent() || optionalUser.get().getSocial() == null) return Optional.empty();
        return Optional.of(optionalUser.get().getSocial().toDTO());
    }

    @Override
    public void updateProfile(String username, UpdateProfileRequest updateProfileRequest){

        User user = userRepository.findByUsername(username).get();

        //이름이 변경되었는지 체크
        if (!user.getName().equals(updateProfileRequest.getName()))
            user.updateName(updateProfileRequest.getName());

        //이메일이 변경되었는지 체크
        if (!user.getEmail().equals(updateProfileRequest.getEmail())) {
            checkDuplicateEmail(updateProfileRequest.getEmail());
            user.updateEmail(updateProfileRequest.getEmail());
        }
    }


    @Override
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
    public UserDetails linkOAuth2Account(String username, String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo) {
        User user = checkRegisteredUser(username);

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
    public OAuth2AccountDTO unlinkOAuth2Account(String username) {
        User user = checkRegisteredUser(username);

        //연관관계 해제
        OAuth2Account oAuth2Account = user.getSocial();
        OAuth2AccountDTO oAuth2AccountDTO = oAuth2Account.toDTO();
        user.unlinkSocial();
        oAuth2AccountRepository.delete(oAuth2Account);

        return oAuth2AccountDTO;
    }

    @Override
    public Optional<OAuth2AccountDTO> withdrawUser(String username) {
        OAuth2AccountDTO oAuth2AccountDTO = null;
        User user = checkRegisteredUser(username);
        //연동된 소셜 계정이 있다면 계정 정보를 리턴하기 위해 저장
        if(user.getSocial() != null)
            oAuth2AccountDTO = user.getSocial().toDTO();
        userRepository.delete(user);
        return oAuth2AccountDTO != null ? Optional.of(oAuth2AccountDTO) : Optional.empty();
    }

    private void checkDuplicateEmail(String email) {
        if(userRepository.existsByEmail(email))
            throw new DuplicateUserException("사용중인 이메일 입니다.", new SimpleFieldError("email", "사용중인 이메일 입니다."));
    }

    private User checkRegisteredUser(String username) {
        Optional<User> optUser = userRepository.findByUsername(username);
        Assert.state(optUser.isPresent(), "가입되지 않은 회원입니다.");
        return optUser.get();
    }
}
