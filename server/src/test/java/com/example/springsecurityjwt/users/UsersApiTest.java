package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.SpringMvcTestSupport;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.security.AuthorityType;
import com.example.springsecurityjwt.util.JsonUtils;
import com.google.gson.reflect.TypeToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.Cookie;
import java.net.URI;
import java.util.Map;
import java.util.Optional;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class UsersApiTest {

    private final Logger log = LoggerFactory.getLogger(UsersApiTest.class);

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private OAuth2AccountRepository oAuth2AccountRepository;
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private final URI AUTHENTICATION_REDIRECT_URI = URI.create("http://localhost:3000/oauth/result");

    @BeforeEach
    public void setup() {
        userRepository.deleteAll();
    }

    @Test
    @Transactional
    public void 회원가입_API_테스트() throws Exception {
        //given
        String email = "test@email.com";
        String name = "ChangHee";
        String password = "password";

        //when
        SignUpRequest signUpRequest = registerTestUser(email, name, password);

        //then
        Optional<User> user = userRepository.findByUsername(signUpRequest.getEmail());
        assertTrue(user.isPresent());
    }

    @Test
    @Transactional
    public void 로그인_유저_프로필_가져오기_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");
        String token = jwtProvider.generateToken(signUpRequest.getEmail());
        Cookie cookie = new Cookie("access_token", token);
        cookie.setMaxAge(60 * 3);
        cookie.setHttpOnly(true);
        cookie.setPath("/");

        //when
        MvcResult mvcResult = mockMvc.perform(get("/users/me")
                .cookie(cookie))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        //then
        String result = mvcResult.getResponse().getContentAsString();
        UserProfileResponse userProfile = JsonUtils.fromJson(result, UserProfileResponse.class);

        assertNotNull(userProfile);
        assertEquals(userProfile.getName(), signUpRequest.getName());
        assertEquals(userProfile.getEmail(), signUpRequest.getEmail());
        assertEquals(userProfile.getAuthorities().get(0), AuthorityType.ROLE_MEMBER);
    }

    @Test
    @Transactional
    public void 로그인된_유저의_연동된_소셜계정_리스트_가져오기_테스트() throws Exception {

        //given
        User user = User.builder().email("test@email.com").name("Changhee").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user);

        OAuth2Account googleAccount = OAuth2Account.builder().provider("google").providerId("123456789").user(user).build();
        OAuth2Account kakaoAccount = OAuth2Account.builder().provider("kakao").providerId("123456789").user(user).build();
        oAuth2AccountRepository.save(googleAccount);
        oAuth2AccountRepository.save(kakaoAccount);

        String token = jwtProvider.generateToken(user.getEmail());
        Cookie cookie = new Cookie("access_token", token);
        cookie.setMaxAge(60 * 3);
        cookie.setHttpOnly(true);
        cookie.setPath("/");

        //when
        MvcResult mvcResult = mockMvc.perform(get("/users/social")
                .cookie(cookie))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        //then
        String result = mvcResult.getResponse().getContentAsString();
        Map<String, Object> accountMap = JsonUtils.fromJson(result, new TypeToken<Map<String, Object>>() {}.getType());

        assertEquals(accountMap.size(), 2);
        assertNotNull(accountMap.get("google"));
        assertNotNull(accountMap.get("kakao"));
    }

    @Test
    @Transactional
    public void 프로필_변경_테스트() throws Exception {
        User user = User.builder().email("test@email.com").name("Changhee").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user);

        String token = jwtProvider.generateToken(user.getEmail());
        Cookie cookie = new Cookie("access_token", token);
        cookie.setMaxAge(60 * 3);
        cookie.setHttpOnly(true);
        cookie.setPath("/");

        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder().name("Updated name").email("test2@email.com").build();
        MvcResult mvcResult = mockMvc.perform(put("/users")
                .cookie(cookie).contentType(MediaType.APPLICATION_JSON_VALUE).content(JsonUtils.toJson(updateProfileRequest)))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        assertEquals(user.getName(), updateProfileRequest.getName());
        assertEquals(user.getEmail(), updateProfileRequest.getEmail());
        assertEquals(user.getUsername(), updateProfileRequest.getEmail());
    }

    private SignUpRequest registerTestUser(String email, String name, String password) throws Exception {
        SignUpRequest signUpRequest = SignUpRequest.builder()
                .email(email)
                .name(name)
                .password(password)
                .build();

        requestSignUpApi(signUpRequest);

        return signUpRequest;
    }

    private void requestSignUpApi(SignUpRequest signUpRequest) throws Exception {
        MvcResult mvcResult = mockMvc.perform(post("/users")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(jsonUtils.toJson(signUpRequest)))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn();
    }
}
