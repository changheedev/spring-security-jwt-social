package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.SpringMvcTestSupport;
import com.example.springsecurityjwt.advice.CommonExceptionAdvice;
import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.users.SignUpRequest;
import com.example.springsecurityjwt.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
public class AuthenticationApiTest extends SpringMvcTestSupport {

    @Autowired
    private JwtProvider jwtProvider;

    private final String GOOGLE_AUTHORIZATION_URI = "https://accounts.google.com/o/oauth2/auth";
    private final String NAVER_AUTHORIZATION_URI = "https://nid.naver.com/oauth2.0/authorize";
    private final String KAKAO_AUTHORIZATION_URI = "https://kauth.kakao.com/oauth/authorize";
    private final String REDIRECT_URI = "http://localhost:3000";

    @Test
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
        assertNotNull(cookie, "토큰 쿠키가 생성되지 않음");
        assertTrue(cookie.getValue().startsWith("eyJhbGciOiJIUzI1NiJ9"), "토큰 정보가 올바르게 생성되지 않음");
        assertTrue(cookie.isHttpOnly(), "쿠키를 생성할 때 옵션이 적용되지 않음");
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
                .andExpect(status().isUnauthorized())
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
        CommonExceptionAdvice.ErrorResponse errorResponse = JsonUtils.fromJson(content, CommonExceptionAdvice.ErrorResponse.class);
        assertEquals(1, errorResponse.getErrors().size(), "Password Null 유효성 검사가 정상적으로 진행되지 않음");
        errorResponse.getErrors().forEach(error -> {
            assertEquals("password", error.getField(), "Password Null 유효성 검사가 정상적으로 진행되지 않음");
            log.debug(error.getField());
            log.debug(error.getDefaultMessage());
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

        MvcResult mvcResult = mockMvc.perform(post("/logout")
                .cookie(cookie))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        assertEquals("", mvcResult.getResponse().getCookie("access_token").getValue(), "토큰 정보가 삭제되지 않음");
    }

    @Test
    public void 인증_토큰이_없을때_로그아웃_요청_실패_테스트() throws Exception {

        MvcResult mvcResult = mockMvc.perform(post("/logout"))
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
        MvcResult mvcResult = mockMvc.perform(get(googleLogin))
                .andExpect(status().isFound())
                .andDo(print()).andReturn();

        //then
        String redirectUri = mvcResult.getResponse().getRedirectedUrl();
        assertTrue(redirectUri.contains(GOOGLE_AUTHORIZATION_URI), "구글 로그인 페이지로 리디렉션 되지 않음");
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
        String redirectUri = mvcResult.getResponse().getRedirectedUrl();
        assertTrue(redirectUri.contains(NAVER_AUTHORIZATION_URI), "네이버 로그인 페이지로 리디렉션 되지 않음");
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
        String redirectUri = mvcResult.getResponse().getRedirectedUrl();
        assertTrue(redirectUri.contains(KAKAO_AUTHORIZATION_URI), "카카오 로그인 페이지로 리디렉션 되지 않음");
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
                .content(JsonUtils.toJson(signUpRequest)))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn();
    }
}
