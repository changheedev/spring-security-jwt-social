package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.SpringTestSupport;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2ProcessException;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2Token;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfoFactory;
import com.example.springsecurityjwt.security.CustomUserDetails;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class UserServiceTest extends SpringTestSupport {

    @Autowired
    private UserService userService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private OAuth2AccountRepository oAuth2AccountRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @Transactional
    public void 회원가입서비스_테스트() {
        //given
        SignUpRequest signUpRequest = SignUpRequest.builder()
                .email("test@email.com")
                .name("ChangHee")
                .password("password")
                .build();

        //when
        userService.signUpService(signUpRequest);

        //then
        Optional<User> optUser = userRepository.findByUsername(signUpRequest.getEmail());

        assertTrue(optUser.isPresent());
        assertEquals(optUser.get().getName(), signUpRequest.getName());
        assertEquals(optUser.get().getAuthorities().size(), 1);
        assertTrue(passwordEncoder.matches(signUpRequest.getPassword(), optUser.get().getPassword()));
    }

    @Test
    @Transactional
    public void 중복된_이메일로_변경을_시도했을때_DuplicatedUsernameException_Throw_테스트() {

        User user1 = User.builder().name("유저1").email("test@email.com").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        User user2 = User.builder().name("유저2").email("test2@email.com").username("test2@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user1);
        userRepository.save(user2);

        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder().name("유저2").email("test@email.com").build();

        assertThrows(DuplicatedUsernameException.class, () -> {
            userService.updateProfile(user2.getUsername(), updateProfileRequest);
        });
    }

    @Test
    @Transactional
    public void 일반_계정의_이메일_변경_시_username이_함께_변경되는지_테스트() {

        User user = User.builder().name("유저").email("test@email.com").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user);

        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder().name("유저2").email("test2@email.com").build();

        userService.updateProfile(user.getUsername(), updateProfileRequest);

        assertEquals(user.getName(), updateProfileRequest.getName());
        assertEquals(user.getEmail(), updateProfileRequest.getEmail());
        assertEquals(user.getUsername(), updateProfileRequest.getEmail());
    }

    @Test
    @Transactional
    public void 소셜_계정의_이메일_변경_시_username이_변경되지_않는지_테스트() {

        User user = User.builder().name("유저").email("test@email.com").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.OAUTH).build();
        userRepository.save(user);

        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder().name("유저2").email("test2@email.com").build();

        userService.updateProfile(user.getUsername(), updateProfileRequest);

        assertEquals(user.getName(), updateProfileRequest.getName());
        assertEquals(user.getEmail(), updateProfileRequest.getEmail());
        assertNotEquals(user.getUsername(), updateProfileRequest.getEmail());
    }

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
        userService.loginOAuth2User("google", oAuth2Token, oAuth2UserInfo);

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
        userService.loginOAuth2User("google", oAuth2Token, oAuth2UserInfo);

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
        CustomUserDetails userDetails = (CustomUserDetails) userService.loginOAuth2User("google", oAuth2Token, oAuth2UserInfo);

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

        OAuth2Account oAuth2Account = OAuth2Account.builder().provider("google").providerId("123456789").token("token").refreshToken("refresh_token").tokenExpiredAt(LocalDateTime.now().plusSeconds(3600)).build();
        oAuth2AccountRepository.save(oAuth2Account);

        user.linkSocial(oAuth2Account);
        userService.unlinkOAuth2Account(user.getUsername());

        //연동된 정보가 삭제되었는지 확인
        assertNull(user.getSocial());
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

        OAuth2Account oAuth2Account = OAuth2Account.builder().provider("google").providerId("123456789").token("token").refreshToken("refresh_token").tokenExpiredAt(LocalDateTime.now().plusSeconds(3600)).build();
        oAuth2AccountRepository.save(oAuth2Account);

        user.linkSocial(oAuth2Account);

        assertThrows(OAuth2ProcessException.class, () -> {
            userService.unlinkOAuth2Account(user.getUsername());
        });
    }

    @Test
    @Transactional
    public void 회원_탈퇴_시_소셜_계정도_함께_삭제되는지_검사() {
        //given
        User user = User.builder()
                .username("test@email.com")
                .email("test@email.com")
                .name("ChangHee")
                .type(UserType.OAUTH)
                .build();
        userRepository.save(user);

        OAuth2Account oAuth2Account = OAuth2Account.builder().provider("google").providerId("123456789").token("token").refreshToken("refresh_token").tokenExpiredAt(LocalDateTime.now().plusSeconds(3600)).build();
        oAuth2AccountRepository.save(oAuth2Account);

        user.linkSocial(oAuth2Account);

        //when
        userService.withdrawUser(user.getUsername());

        //then
        assertFalse(userRepository.findByUsername(user.getUsername()).isPresent());
        assertFalse(oAuth2AccountRepository.findByProviderAndProviderId("google", "123456789").isPresent());
    }
}
