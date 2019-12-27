package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.SpringMvcTestSupport;
import com.example.springsecurityjwt.authentication.AuthenticationService;
import com.example.springsecurityjwt.jwt.JWT;
import com.example.springsecurityjwt.security.AuthorityType;
import com.example.springsecurityjwt.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.Cookie;
import java.net.URI;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
    private AuthenticationService authenticationService;

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
        JWT token = authenticationService.issueToken(signUpRequest.getEmail());
        Cookie cookie = new Cookie("access_token", token.getToken());
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
