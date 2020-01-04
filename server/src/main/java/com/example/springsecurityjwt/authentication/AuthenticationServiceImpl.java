package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.authentication.oauth2.OAuth2ProcessException;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
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
    public UserDetails loadUser(String registrationId, OAuth2UserInfo userInfo) {

        Optional<OAuth2Account> oAuth2Account = oAuth2AccountRepository.findByProviderAndProviderId(registrationId, userInfo.getId());
        User user = null;

        //가입된 계정이 존재할때
        if (oAuth2Account.isPresent()) {
            user = oAuth2Account.get().getUser();
        }
        //가입된 계정이 존재하지 않을때
        else {
            //이메일 정보가 있을때
            if (userInfo.getEmail() != null) {
                // 같은 이메일을 사용하는 계정이 존재하는지 확인 후 있다면 소셜 계정과 연결시키고 없다면 새로 생성한다
                user = userRepository.findByEmail(userInfo.getEmail())
                        .orElse(User.builder()
                                .username(registrationId + "_" + userInfo.getId())
                                .name(userInfo.getName())
                                .email(userInfo.getEmail())
                                .type(UserType.OAUTH)
                                .build());
            }
            //이메일 정보가 없을때
            else {
                user = User.builder()
                        .username(registrationId + "_" + userInfo.getId())
                        .name(userInfo.getName())
                        .type(UserType.OAUTH)
                        .build();
            }

            //새로 생성된 유저이면 db에 저장
            if(user.getId() == null)
                userRepository.save(user);

            OAuth2Account newAccount = OAuth2Account.builder().provider(registrationId).providerId(userInfo.getId()).user(user).build();
            oAuth2AccountRepository.save(newAccount);
        }

        CustomUserDetails userDetails = CustomUserDetails.builder().id(user.getId()).username(user.getUsername()).name(user.getName()).email(user.getEmail()).authorities(user.getAuthorities()).build();
        return userDetails;
    }

    @Override
    @Transactional
    public UserDetails linkAccount(String targetUsername, String registrationId, OAuth2UserInfo userInfo) {

        if (oAuth2AccountRepository.existsByProviderAndProviderId(registrationId, userInfo.getId()))
            throw new OAuth2ProcessException("This account is already linked");

        User user = userRepository.findByUsername(targetUsername)
                .orElseThrow(() -> new UsernameNotFoundException("Member not found"));

        OAuth2Account oAuth2Account = OAuth2Account.builder()
                .provider(registrationId)
                .providerId(userInfo.getId())
                .user(user)
                .build();

        oAuth2AccountRepository.save(oAuth2Account);

        return CustomUserDetails.builder().id(user.getId()).username(user.getUsername()).name(user.getName()).email(user.getEmail()).authorities(user.getAuthorities()).build();
    }

    @Override
    @Transactional
    public void unlinkAccount(String provider, OAuth2UserInfo userInfo, Long userId) {
        //연동해제 요청시 진행한 인증 과정에서 동일한 계정으로 인증되었는지 검사
        if(!oAuth2AccountRepository.existsByProviderAndProviderIdAndUserId(provider, userInfo.getId(), userId))
            throw new OAuth2ProcessException("This account does not exist");

        oAuth2AccountRepository.deleteByProviderAndProviderIdAndUserId(provider, userInfo.getId(), userId);
    }
}
