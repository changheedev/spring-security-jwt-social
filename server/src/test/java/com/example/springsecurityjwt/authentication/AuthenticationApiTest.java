package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.SpringMvcTestSupport;
import com.example.springsecurityjwt.advice.CommonExceptionAdvice;
import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.users.SignUpRequest;
import com.example.springsecurityjwt.users.UserRepository;
import com.example.springsecurityjwt.util.JsonUtils;
import com.google.gson.reflect.TypeToken;
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
import java.util.List;

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
    private JwtProvider jwtProvider;

    private final String GOOGLE_AUTHORIZATION_URI = "https://accounts.google.com/o/oauth2/auth";
    private final String NAVER_AUTHORIZATION_URI = "https://nid.naver.com/oauth2.0/authorize";
    private final String KAKAO_AUTHORIZATION_URI = "https://kauth.kakao.com/oauth/authorize";
    private final String REDIRECT_URI = "http://localhost:3000";

    @Test
    @Transactional
    public void Cookie_AccessToken_발급_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");
        AuthorizationRequest authorizationRequest = AuthorizationRequest.builder()
                .username(signUpRequest.getEmail())
                .password(signUpRequest.getPassword())
                .build();

        //when
        MvcResult mvcResult = mockMvc.perform(post("/authorize")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(authorizationRequest)))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        //then
        Cookie cookie = mvcResult.getResponse().getCookie("access_token");
        assertNotNull(cookie);
        assertTrue(cookie.getValue().startsWith("eyJhbGciOiJIUzI1NiJ9"));
        assertTrue(cookie.isHttpOnly());
    }

    @Test
    public void 틀린_이메일_또는_비밀번호를_사용할때_로그인_실패_테스트() throws Exception {

        //given
        AuthorizationRequest authorizationRequest = AuthorizationRequest.builder()
                .username("not_registerd@email.com")
                .password("password")
                .build();

        //when
        MvcResult mvcResult = mockMvc.perform(post("/authorize")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(authorizationRequest)))
                .andExpect(status().isBadRequest())
                .andDo(print()).andReturn();
    }

    @Test
    public void 로그인_validation_테스트() throws Exception {

        //given
        AuthorizationRequest authorizationRequest = AuthorizationRequest.builder()
                .username("not_registerd@email.com")
                .password("")
                .build();

        //when
        MvcResult mvcResult = mockMvc.perform(post("/authorize")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(authorizationRequest)))
                .andExpect(status().isBadRequest())
                .andDo(print()).andReturn();

        //then
        String content = mvcResult.getResponse().getContentAsString();
        List<CommonExceptionAdvice.ValidationError> errors = JsonUtils.fromJson(content, new TypeToken<List<CommonExceptionAdvice.ValidationError>>(){}.getType());
        assertEquals(errors.size(), 1);
        errors.forEach(error -> {
            assertEquals(error.getField(), "password");
            log.debug(error.getField());
            log.debug(error.getMessage());
        });

    }

    @Test
    public void 로그아웃_테스트() throws Exception {

        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");
        String token = jwtProvider.generateToken(signUpRequest.getEmail());
        Cookie cookie = new Cookie("access_token", token);
        cookie.setMaxAge(60 * 3);
        cookie.setHttpOnly(true);
        cookie.setPath("/");

        MvcResult mvcResult = mockMvc.perform(post("/authorize/logout")
                .cookie(cookie))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        assertEquals(mvcResult.getResponse().getCookie("access_token").getValue(), "");
    }

    @Test
    public void 인증_토큰이_없을때_로그아웃_요청_실패_테스트() throws Exception {

        MvcResult mvcResult = mockMvc.perform(post("/authorize/logout"))
                .andExpect(status().isUnauthorized())
                .andDo(print()).andReturn();
    }

    @Test
    public void 구글로그인_요청_리디렉션_테스트() throws Exception {

        //given
        String googleLogin = UriComponentsBuilder.fromUriString("/oauth2/authorize/google")
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("callback", "login")
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
    }

    @Test
    public void 네이버로그인_요청_리디렉션_테스트() throws Exception {

        //given
        String naverLogin = UriComponentsBuilder.fromUriString("/oauth2/authorize/naver")
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("callback", "login")
                .build().encode(StandardCharsets.UTF_8).toUriString();

        //when
        MvcResult mvcResult = mockMvc.perform(get(naverLogin))
                .andExpect(status().isFound())
                .andDo(print()).andReturn();

        //then
        //소셜 서비스에서 제공하는 인증 페이지로 리디렉션 된다.
        String redirectUri = mvcResult.getResponse().getRedirectedUrl();
        assertTrue(redirectUri.contains(NAVER_AUTHORIZATION_URI));
    }

    @Test
    public void 카카오로그인_요청_리디렉션_테스트() throws Exception {

        //given
        String kakaoLogin = UriComponentsBuilder.fromUriString("/oauth2/authorize/kakao")
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("callback", "login")
                .build().encode(StandardCharsets.UTF_8).toUriString();

        //when
        MvcResult mvcResult = mockMvc.perform(get(kakaoLogin))
                .andExpect(status().isFound())
                .andDo(print()).andReturn();

        //then
        //소셜 서비스에서 제공하는 인증 페이지로 리디렉션 된다.
        String redirectUri = mvcResult.getResponse().getRedirectedUrl();
        assertTrue(redirectUri.contains(KAKAO_AUTHORIZATION_URI));
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
