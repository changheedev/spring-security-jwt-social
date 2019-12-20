package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.SpringMvcTestSupport;
import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.users.SignUpRequest;
import com.example.springsecurityjwt.users.User;
import com.example.springsecurityjwt.users.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class AuthenticationApiTest {

    private final Logger log = LoggerFactory.getLogger(AuthenticationApiTest.class);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private AuthenticationService authenticationService;
    @Autowired
    private JwtProvider jwtProvider;

    private final String AUTHORIZATION_CODE_REG_EXP = "[0-9a-fA-F]{8}[0-9a-fA-F]{4}[0-9a-fA-F]{4}[0-9a-fA-F]{4}[0-9a-fA-F]{12}";

    private final String BASE_REDIRECT_URI = "http://localhost:3000/oauth2/callback";
    private final String GOOGLE_REDIRECT_URI = BASE_REDIRECT_URI + "/google";
    private final String NAVER_REDIRECT_URI = BASE_REDIRECT_URI + "/naver";
    private final String KAKAO_REDIRECT_URI = BASE_REDIRECT_URI + "/kakao";
    private final String GOOGLE_AUTHORIZATION_URI = "https://accounts.google.com/o/oauth2/auth";
    private final String NAVER_AUTHORIZATION_URI = "https://nid.naver.com/oauth2.0/authorize";
    private final String KAKAO_AUTHORIZATION_URI = "https://kauth.kakao.com/oauth/authorize";

    @BeforeEach
    public void setup() {
        userRepository.deleteAll();
    }

    @Test
    @Transactional
    public void 인증_후_Authorization_Code_리디렉션_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");
        AuthenticationRequest authenticationRequest = AuthenticationRequest.builder()
                .username(signUpRequest.getEmail())
                .password(signUpRequest.getPassword())
                .build();

        //when
        MvcResult mvcResult = mockMvc.perform(post("/authorize")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(authenticationRequest)))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        //then
        String result = mvcResult.getResponse().getContentAsString();
        AccessTokenResponse tokenResponse = JsonUtils.fromJson(result, AccessTokenResponse.class);
        assertNotNull(tokenResponse.getToken());
        assertNotNull(tokenResponse.getRefreshToken());
    }

    @Test
    public void 구글로그인_요청_리디렉션_테스트() throws Exception {

        //given
        String googleLogin = UriComponentsBuilder.fromUriString("/oauth2/authorize/google")
                .queryParam("redirectUri", GOOGLE_REDIRECT_URI)
                .build().encode(StandardCharsets.UTF_8).toUriString();

        //when
        MvcResult result = mockMvc.perform(post("/oauth2/attributes")
                .cookie(new Cookie("redirect_uri", AUTHENTICATION_REDIRECT_URI.toString()))
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(jsonUtils.toJson(oAuth2AdditionalAttributesRequest)))
                .andExpect(status().isFound())
                .andDo(print()).andReturn();

        //then
        //소셜 서비스에서 제공하는 인증 페이지로 리디렉션 된다.
        String redirectUri = mvcResult.getResponse().getRedirectedUrl();
        assertTrue(redirectUri.contains(GOOGLE_AUTHORIZATION_URI));
        assertTrue(redirectUri.contains(GOOGLE_REDIRECT_URI));
    }

    @Test
    public void 네이버로그인_요청_리디렉션_테스트() throws Exception {

        //given
        String naverLogin = UriComponentsBuilder.fromUriString("/oauth2/authorize/naver")
                .queryParam("redirectUri", NAVER_REDIRECT_URI)
                .build().encode(StandardCharsets.UTF_8).toUriString();

        //when
        MvcResult mvcResult = mockMvc.perform(get(naverLogin))
                .andExpect(status().isFound())
                .andDo(print()).andReturn();

        //then
        //소셜 서비스에서 제공하는 인증 페이지로 리디렉션 된다.
        String redirectUri = mvcResult.getResponse().getRedirectedUrl();
        assertTrue(redirectUri.contains(NAVER_AUTHORIZATION_URI));
        assertTrue(redirectUri.contains(NAVER_REDIRECT_URI));
    }

    @Test
    public void 카카오로그인_요청_리디렉션_테스트() throws Exception {

        //given
        String kakaoLogin = UriComponentsBuilder.fromUriString("/oauth2/authorize/kakao")
                .queryParam("redirectUri", KAKAO_REDIRECT_URI)
                .build().encode(StandardCharsets.UTF_8).toUriString();

        //when
        MvcResult mvcResult = mockMvc.perform(get(kakaoLogin))
                .andExpect(status().isFound())
                .andDo(print()).andReturn();

        //then
        //소셜 서비스에서 제공하는 인증 페이지로 리디렉션 된다.
        String redirectUri = mvcResult.getResponse().getRedirectedUrl();
        assertTrue(redirectUri.contains(KAKAO_AUTHORIZATION_URI));
        assertTrue(redirectUri.contains(KAKAO_REDIRECT_URI));
    }

    @Test
    @Transactional
    public void 토큰_재발급_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");
        CustomUserDetails userDetails = CustomUserDetails.builder().username(signUpRequest.getEmail()).email(signUpRequest.getEmail()).name(signUpRequest.getName()).build();
        AccessTokenResponse accessTokenResponse = authenticationService.issueAccessToken(userDetails);

        //when
        MvcResult mvcResult = mockMvc.perform(post("/authorize/refresh_token")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(new RefreshTokenRequest(accessTokenResponse.getRefreshToken()))))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        //then
        String result = mvcResult.getResponse().getContentAsString();
        AccessTokenResponse tokenResponse = JsonUtils.fromJson(result, AccessTokenResponse.class);
        assertNotEquals(accessTokenResponse.getToken(), tokenResponse.getToken(), "토큰이 재발급 되지 않음.");
        assertEquals(accessTokenResponse.getRefreshToken(), tokenResponse.getRefreshToken(), "만료기간이 한달 이상 남은 리프레쉬 토큰이 재발급 됨.");

    }

    @Test
    @Transactional
    public void Refresh_Token_만료_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");
        UserDetails userDetails = authenticationService.authenticateUsernamePassword(signUpRequest.getEmail(), signUpRequest.getPassword());
        AccessTokenResponse accessTokenResponse = authenticationService.issueAccessToken(userDetails);

        //when
        MvcResult mvcResult = mockMvc.perform(delete("/authorize/refresh_token")
                .header("Authorization", "Bearer " + accessTokenResponse.getToken())
                )
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        //then
        Optional<RefreshToken> optRefreshToken = refreshTokenRepository.findByUsername(userDetails.getUsername());
        assertFalse(optRefreshToken.isPresent(), "refresh token 이 삭제되지 않음.");
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
