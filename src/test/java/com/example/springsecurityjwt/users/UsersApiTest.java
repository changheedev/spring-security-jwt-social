package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.SpringMvcTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;
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
    private ObjectMapper objectMapper;

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
        Optional<User> user = userRepository.findByEmail(signUpRequest.getEmail());
        assertTrue(user.isPresent());
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
