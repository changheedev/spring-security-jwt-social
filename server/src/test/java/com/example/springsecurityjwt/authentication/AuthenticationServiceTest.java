package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.SpringTestSupport;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2ProcessException;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfoFactory;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.users.User;
import com.example.springsecurityjwt.users.UserRepository;
import com.example.springsecurityjwt.users.UserType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class AuthenticationServiceTest extends SpringTestSupport {

    @Autowired
    private AuthenticationService authenticationService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private OAuth2AccountRepository oAuth2AccountRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @Transactional
    public void 중복된_이메일이_존재할_경우_계정_연동_테스트() {
        //given
        User user = User.builder()
                .username("test@email.com")
                .email("test@email.com")
                .name("ChangHee")
                .password(passwordEncoder.encode("password"))
                .type(UserType.DEFAULT)
                .build();
        userRepository.save(user);
        userRepository.flush();

        Map<String, Object> attributes = new HashMap<>();

        attributes.put("id", "123456789");
        attributes.put("email", "test@email.com");
        attributes.put("name", "oauthUser");

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo("google", attributes);

        //when
        authenticationService.loadUser("google", oAuth2UserInfo);

        //then
        Optional<OAuth2Account> optOAuth2Account = oAuth2AccountRepository.findByProviderAndProviderId("google", "123456789");
        assertTrue(optOAuth2Account.isPresent());

        User linkedUser = optOAuth2Account.get().getUser();
        assertEquals(linkedUser.getId(), user.getId());
        assertEquals(linkedUser.getName(), user.getName());
        assertEquals(linkedUser.getEmail(), user.getEmail());
    }

    @Test
    @Transactional
    public void 이메일이_중복되지_않는_경우_계정_생성_테스트() {
        //given
        User user = User.builder()
                .username("test@email.com")
                .email("test@email.com")
                .name("ChangHee")
                .password(passwordEncoder.encode("password"))
                .type(UserType.DEFAULT)
                .build();
        userRepository.save(user);
        userRepository.flush();

        Map<String, Object> attributes = new HashMap<>();

        attributes.put("id", "123456789");
        attributes.put("email", "test2@email.com");
        attributes.put("name", "oauthUser");

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo("google", attributes);

        //when
        authenticationService.loadUser("google", oAuth2UserInfo);

        //then
        Optional<OAuth2Account> optOAuth2Account = oAuth2AccountRepository.findByProviderAndProviderId("google", "123456789");
        assertTrue(optOAuth2Account.isPresent());

        User linkedUser = optOAuth2Account.get().getUser();
        assertNotEquals(linkedUser.getId(), user.getId());
        assertEquals(linkedUser.getName(), oAuth2UserInfo.getName());
        assertEquals(linkedUser.getEmail(), oAuth2UserInfo.getEmail());
    }

    @Test
    @Transactional
    public void 계정_생성_이후_소셜_로그인_테스트() {

        Map<String, Object> attributes = new HashMap<>();

        attributes.put("id", "123456789");
        attributes.put("email", "test@email.com");
        attributes.put("name", "oauthUser");

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo("google", attributes);

        //when
        CustomUserDetails userDetails1 = (CustomUserDetails) authenticationService.loadUser("google", oAuth2UserInfo);
        CustomUserDetails userDetails2 = (CustomUserDetails) authenticationService.loadUser("google", oAuth2UserInfo);

        //then
        assertEquals(userDetails1.getId(), userDetails2.getId());
    }

    @Test
    @Transactional
    public void 이메일_정보가_없을_때_소셜_로그인_테스트() {

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("id", "123456789");
        attributes.put("name", "oauthUser");

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo("google", attributes);

        //when
        CustomUserDetails userDetails = (CustomUserDetails) authenticationService.loadUser("google", oAuth2UserInfo);

        //then
        assertNull(userDetails.getEmail());
        assertEquals(userDetails.getUsername(), "google_123456789");
        assertEquals(userDetails.getName(), "oauthUser");
    }

    @Test
    @Transactional
    public void 연동해제_테스트() {
        //given
        User user = User.builder()
                .username("test@email.com")
                .email("test@email.com")
                .name("ChangHee")
                .password(passwordEncoder.encode("password"))
                .type(UserType.DEFAULT)
                .build();
        userRepository.save(user);

        OAuth2Account oAuth2Account = OAuth2Account.builder().provider("google").providerId("123456789").user(user).build();
        oAuth2AccountRepository.save(oAuth2Account);

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("id", "123456789");
        attributes.put("email", "test@email.com");
        attributes.put("name", "oauthUser");
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo("google", attributes);

        authenticationService.unlinkAccount("google", oAuth2UserInfo, user.getId());

        //연동된 정보가 존재하지 않는지 확인
        assertFalse(oAuth2AccountRepository.existsByProviderAndProviderIdAndUserId("google", "123456789", user.getId()));
    }

    @Test
    @Transactional
    public void 연동한_계정과_다른_계정으로_인증된_경우_연동해제_실패_테스트() {

        //given
        User user = User.builder()
                .username("test@email.com")
                .email("test@email.com")
                .name("ChangHee")
                .password(passwordEncoder.encode("password"))
                .type(UserType.DEFAULT)
                .build();
        userRepository.save(user);

        OAuth2Account oAuth2Account = OAuth2Account.builder().provider("google").providerId("123456789").user(user).build();
        oAuth2AccountRepository.save(oAuth2Account);

        Map<String, Object> attributes = new HashMap<>();

        attributes.put("id", "12345678910"); //다른 id 값이 리턴 된 경우
        attributes.put("email", "test@email.com");
        attributes.put("name", "oauthUser");

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo("google", attributes);

        //연동된 계정과 다른 계정으로 인증된 경우 OAuth2ProcessException 을 던진다
        assertThrows(OAuth2ProcessException.class, () -> {
            authenticationService.unlinkAccount("google", oAuth2UserInfo, user.getId());
        });
    }
}
