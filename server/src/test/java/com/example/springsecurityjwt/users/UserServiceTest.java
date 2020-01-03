package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.SpringTestSupport;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.security.CustomUserDetailsService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest
public class UserServiceTest {

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
    public void 연동된_소셜계정_리스트_불러오기_테스트() {
        //given
        User user = User.builder().email("test@email.com").name("Changhee").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user);

        OAuth2Account googleAccount = OAuth2Account.builder().provider("google").providerId("123456789").user(user).build();
        OAuth2Account kakaoAccount = OAuth2Account.builder().provider("kakao").providerId("123456789").user(user).build();
        oAuth2AccountRepository.save(googleAccount);
        oAuth2AccountRepository.save(kakaoAccount);

        //when
        Map<String, Object> accountMap = userService.getLinkedSocialAccountMap("test@email.com");

        //then
        assertEquals(accountMap.size(), 2);
        assertNotNull(accountMap.get("google"));
        assertNotNull(accountMap.get("kakao"));
        log.debug(accountMap.get("google").toString());
        log.debug(accountMap.get("kakao").toString());
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
}
