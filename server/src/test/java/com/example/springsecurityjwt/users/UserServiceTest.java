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

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
@SpringBootTest
public class UserServiceTest {

    @Autowired
    private UserService userService;
    @Autowired
    private CustomUserDetailsService userDetailsService;
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
        CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(signUpRequest.getEmail());

        assertEquals(userDetails.getName(), signUpRequest.getName());
        assertEquals(userDetails.getAuthorities().size(), 1);
        assertEquals(passwordEncoder.matches(signUpRequest.getPassword(), userDetails.getPassword()), true);
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
}
