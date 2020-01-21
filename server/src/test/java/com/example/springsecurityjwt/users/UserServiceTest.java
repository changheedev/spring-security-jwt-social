package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.SpringTestSupport;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2Token;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountDTO;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfoFactory;
import com.example.springsecurityjwt.security.UserDetailsImpl;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@Transactional
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
    public void 회원가입서비스_테스트() {
        //given
        SignUpRequest signUpRequest = SignUpRequest.builder()
                .email("test@email.com")
                .name("ChangHee")
                .password("password")
                .build();

        //when
        userService.saveUser(signUpRequest);

        //then
        Optional<User> optUser = userRepository.findByUsername(signUpRequest.getEmail());

        assertTrue(optUser.isPresent(), "회원가입 과정에서 유저 정보가 정상적으로 저장되지 않음");
        assertEquals(signUpRequest.getName(), optUser.get().getName(), "가입 요청된 이름과 가입 된 이름이 다름");
        assertEquals(1, optUser.get().getAuthorities().size(), "기본 권한 외에 다른 권한이 등록됨");
        assertTrue(passwordEncoder.matches(signUpRequest.getPassword(), optUser.get().getPassword()), "저장된 패스워드가 매칭되지 않음");
    }

    @Test
    public void 중복된_이메일로_변경을_시도했을때_DuplicatedUsernameException_Throw_테스트() {

        User user1 = User.builder().name("유저1").email("test@email.com").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        User user2 = User.builder().name("유저2").email("test2@email.com").username("test2@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user1);
        userRepository.save(user2);

        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder().name("유저2").email("test@email.com").build();

        assertThrows(DuplicateUserException.class, () -> {
            userService.updateProfile(user2.getUsername(), updateProfileRequest);
        }, "중복된 이메일로 변경할 때 DuplicateUserException 이 던져지지 않음");
    }

    @Test
    public void 일반_계정의_이메일_변경_시_username이_함께_변경되는지_테스트() {

        User user = User.builder().name("유저").email("test@email.com").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user);

        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder().name("유저").email("test2@email.com").build();

        userService.updateProfile(user.getUsername(), updateProfileRequest);

        assertEquals(user.getEmail(), updateProfileRequest.getEmail(), "이메일이 업데이트 되지 않음");
        assertEquals(user.getUsername(), updateProfileRequest.getEmail(), "username 이 함께 업데이트 되지 않음");
    }

    @Test
    public void 소셜_계정의_이메일_변경_시_username이_변경되지_않는지_테스트() {

        User user = User.builder().name("유저").email("test@email.com").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.OAUTH).build();
        userRepository.save(user);

        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder().name("유저").email("test2@email.com").build();

        userService.updateProfile(user.getUsername(), updateProfileRequest);

        assertEquals(user.getEmail(), updateProfileRequest.getEmail(), "이메일이 업데이트 되지 않음");
        assertNotEquals(user.getUsername(), updateProfileRequest.getEmail(), "소셜 서비스로 생성된 계정의 username 이 함께 변경됨");
    }

    @Test
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
        assertTrue(optOAuth2Account.isPresent(), "소셜 계정 정보가 정상적으로 저장되지 않음");

        User linkedUser = optOAuth2Account.get().getUser();
        assertEquals(user.getId(), linkedUser.getId(),"소셜 계정과 같은 이메일을 사용하는 계정이 연동되지 않음");
    }

    @Test
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
        assertTrue(optOAuth2Account.isPresent(), "소셜 계정 정보가 정상적으로 저장되지 않음");

        User linkedUser = optOAuth2Account.get().getUser();
        assertNotEquals(user.getId(), linkedUser.getId(), "소셜 계정과 이메일이 중복되지 않는 계정과 연동됨");
        assertTrue(linkedUser.getUsername().startsWith("google_"), "소셜 서비스로 가입된 계정의 username 이 올바른 형식으로 생성되지 않음");
    }

    @Test
    public void 이메일_정보가_없을_때_소셜_로그인_테스트() {

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("id", "123456789");
        attributes.put("name", "oauthUser");

        OAuth2Token oAuth2Token = new OAuth2Token("access_token", "refresh_token", LocalDateTime.now().plusSeconds(3600));
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo("google", attributes);

        //when
        UserDetailsImpl userDetails = (UserDetailsImpl) userService.loginOAuth2User("google", oAuth2Token, oAuth2UserInfo);

        //then
        assertNull(userDetails.getEmail(), "이메일 정보가 없는 소셜 서비스로 가입한 계정에 이메일 정보가 등록됨");
        assertEquals("google_123456789", userDetails.getUsername(), "소셜 서비스로 가입된 계정의 username 이 올바른 형식으로 생성되지 않음");
    }

    @Test
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
        assertNull(user.getSocial(), "연동 관계가 해제되지 않음.");
        assertFalse(oAuth2AccountRepository.existsByProviderAndProviderId("google", "123456789"), "연동 해제된 소셜계정 정보가 삭제되지 않음");
    }

    @Test
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

        assertThrows(IllegalStateException.class, () -> {
            userService.unlinkOAuth2Account(user.getUsername());
        }, "소셜 서비스로 가입된 계정의 연동해제 과정에서 IllegalStateException 이 던져지지 않음");
    }

    @Test
    public void 연동된_소셜_계정이_없을때_withdrawUser_메소드에서_Optional_empty_를_반환하는지_테스트() {
        //given
        User user = User.builder()
                .username("test@email.com")
                .email("test@email.com")
                .name("ChangHee")
                .type(UserType.OAUTH)
                .build();
        userRepository.save(user);

        //when
        Optional<OAuth2AccountDTO> optionalOAuth2AccountDTO = userService.withdrawUser(user.getUsername());

        //then
        assertFalse(optionalOAuth2AccountDTO.isPresent());
    }

    @Test
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
        assertFalse(userRepository.findByUsername(user.getUsername()).isPresent(), "회원 탈퇴 후 계정 정보가 삭제되지 않음");
        assertFalse(oAuth2AccountRepository.findByProviderAndProviderId("google", "123456789").isPresent(), "회원 탈퇴 후 연동 되었던 소셜 계정 정보가 함께 삭제되지 않음");
    }
}
