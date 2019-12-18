package com.example.springsecurityjwt.oauth2;

import com.example.springsecurityjwt.SpringTestSupport;
import com.example.springsecurityjwt.users.User;
import com.example.springsecurityjwt.users.UserRepository;
import com.example.springsecurityjwt.users.UserType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class OAuth2ServiceTest extends SpringTestSupport {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private OAuth2AccountRepository oAuth2AccountRepository;
    @Autowired
    private OAuth2AuthenticationService oAuth2AuthenticationService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @Transactional
    public void 중복된_이메일이_존재할_경우_계정_연동_테스트() {
        //given
        User user = User.builder()
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
        oAuth2AuthenticationService.loadUser("google", oAuth2UserInfo);

        //then
        Optional<OAuth2Account> optOAuth2Account = oAuth2AccountRepository.findByProviderAndProviderId("google", "123456789");
        assertTrue(optOAuth2Account.isPresent());
        assertEquals(optOAuth2Account.get().getUserId(), user.getId());

        Optional<User> optUser = userRepository.findById(optOAuth2Account.get().getUserId());
        assertTrue(optUser.isPresent());
        assertEquals(optUser.get().getName(), user.getName());
        assertEquals(optUser.get().getEmail(), user.getEmail());
    }

    @Test
    @Transactional
    public void 이메일이_중복되지_않는_경우_계정_생성_테스트() {
        //given
        User user = User.builder()
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
        oAuth2AuthenticationService.loadUser("google", oAuth2UserInfo);

        //then
        Optional<OAuth2Account> optOAuth2Account = oAuth2AccountRepository.findByProviderAndProviderId("google", "123456789");
        assertTrue(optOAuth2Account.isPresent());
        assertNotEquals(optOAuth2Account.get().getUserId(), user.getId());

        Optional<User> optUser = userRepository.findById(optOAuth2Account.get().getUserId());
        assertTrue(optUser.isPresent());
        assertEquals(optUser.get().getName(), oAuth2UserInfo.getName());
        assertEquals(optUser.get().getEmail(), oAuth2UserInfo.getEmail());
    }
}

