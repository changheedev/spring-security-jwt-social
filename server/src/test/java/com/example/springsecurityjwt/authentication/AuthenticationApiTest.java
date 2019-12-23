package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.SpringMvcTestSupport;
import com.example.springsecurityjwt.users.SignUpRequest;
import com.example.springsecurityjwt.users.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
    public void AccessToken_발급_테스트() throws Exception {

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
    @Transactional
    public void Cookie_AccessToken_발급_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");
        AuthenticationRequest authenticationRequest = AuthenticationRequest.builder()
                .username(signUpRequest.getEmail())
                .password(signUpRequest.getPassword())
                .responseType("cookie")
                .build();

        //when
        MvcResult mvcResult = mockMvc.perform(post("/authorize")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(authenticationRequest)))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        //then
        Cookie cookie = mvcResult.getResponse().getCookie("access_token");
        assertNotNull(cookie);
        assertTrue(cookie.isHttpOnly());
    }

    @Test
    @Transactional
    public void 토큰_재발급_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");
        AccessTokenResponse oldToken = authenticationService.issueToken(signUpRequest.getEmail());

        //when
        Thread.sleep(1000);
        MvcResult mvcResult = mockMvc.perform(post("/authorize/refresh_token")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(new RefreshTokenRequest(oldToken.getToken(), oldToken.getRefreshToken()))))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        //then
        String result = mvcResult.getResponse().getContentAsString();
        AccessTokenResponse newToken = JsonUtils.fromJson(result, AccessTokenResponse.class);
        assertNotEquals(oldToken.getToken(), newToken.getToken(), "토큰이 재발급 되지 않음.");
        assertEquals(oldToken.getRefreshToken(), newToken.getRefreshToken(), "만료기간이 한달 이상 남은 리프레쉬 토큰이 재발급 됨.");
    }

    @Test
    @Transactional
    public void 로그아웃시_Refresh_Token_만료_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");
        AccessTokenResponse accessTokenResponse = authenticationService.issueToken(signUpRequest.getEmail());

        //when
        MvcResult mvcResult = mockMvc.perform(post("/authorize/logout")
                .header("Authorization", "Bearer " + accessTokenResponse.getToken()))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        //then
        Optional<RefreshToken> optRefreshToken = refreshTokenRepository.findByUsername(signUpRequest.getEmail());
        assertFalse(optRefreshToken.isPresent(), "refresh token 이 삭제되지 않음.");
    }

    @Test
    @Transactional
    public void 로그아웃시_Token_Cookie_만료_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");
        AccessTokenResponse accessTokenResponse = authenticationService.issueToken(signUpRequest.getEmail());
        Cookie cookie = new Cookie("access_token", accessTokenResponse.getToken());
        cookie.setMaxAge(60 * 60 * 24 * 7);
        cookie.setHttpOnly(true);
        cookie.setPath("/");

        //when
        MvcResult mvcResult = mockMvc.perform(post("/authorize/logout")
                .cookie(cookie))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        //then
        Cookie responseCookie = mvcResult.getResponse().getCookie("access_token");
        assertEquals(responseCookie.getMaxAge(), 0);
        assertEquals(responseCookie.getValue(), "");
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
