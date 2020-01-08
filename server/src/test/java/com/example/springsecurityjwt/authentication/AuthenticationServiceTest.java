package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.SpringTestSupport;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2ProcessException;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2Token;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfoFactory;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.users.User;
import com.example.springsecurityjwt.users.UserRepository;
import com.example.springsecurityjwt.users.UserType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
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

        OAuth2Token oAuth2Token = new OAuth2Token("access_token", "refresh_token", LocalDateTime.now().plusSeconds(3600));
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo("google", attributes);

        //when
        authenticationService.registerOrLoadOAuth2User("google", oAuth2Token, oAuth2UserInfo);

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
    public void 소셜계정의_이메일이_중복되지_않는_경우_새로운_계정이_생성되는지_테스트() {
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

        OAuth2Token oAuth2Token = new OAuth2Token("access_token", "refresh_token", LocalDateTime.now().plusSeconds(3600));
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo("google", attributes);

        //when
        authenticationService.registerOrLoadOAuth2User("google", oAuth2Token, oAuth2UserInfo);

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
    public void 이메일_정보가_없을_때_소셜_로그인_테스트() {

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("id", "123456789");
        attributes.put("name", "oauthUser");

        OAuth2Token oAuth2Token = new OAuth2Token("access_token", "refresh_token", LocalDateTime.now().plusSeconds(3600));
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo("google", attributes);

        //when
        CustomUserDetails userDetails = (CustomUserDetails) authenticationService.registerOrLoadOAuth2User("google", oAuth2Token, oAuth2UserInfo);

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

        authenticationService.unlinkOAuth2Account("google", "123456789", user.getId());

        //연동된 정보가 삭제되었는지 확인
        assertFalse(oAuth2AccountRepository.existsByProviderAndProviderId("google", "123456789"));
    }

    @Test
    @Transactional
    public void Account_Type_이_OAUTH_인_경우_연동해제_실패_테스트() {
        //given
        User user = User.builder()
                .username("test@email.com")
                .email("test@email.com")
                .name("ChangHee")
                .type(UserType.OAUTH)
                .build();
        userRepository.save(user);

        OAuth2Account oAuth2Account = OAuth2Account.builder().provider("google").providerId("123456789").user(user).build();
        oAuth2AccountRepository.save(oAuth2Account);

        assertThrows(OAuth2ProcessException.class, () -> {
            authenticationService.unlinkOAuth2Account("google", "123456789", user.getId());
        });
    }
}
