package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.SpringMvcTestSupport;
import com.example.springsecurityjwt.advice.CommonExceptionAdvice;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.security.AuthorityType;
import com.example.springsecurityjwt.util.JsonUtils;
import com.google.gson.reflect.TypeToken;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.Cookie;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class UsersApiTest extends SpringMvcTestSupport{

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private OAuth2AccountRepository oAuth2AccountRepository;
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private PasswordEncoder passwordEncoder;

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
    public void 회원가입_Null_Valid_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = SignUpRequest.builder().email("").name("").password("").build();

        //when
        MvcResult mvcResult = mockMvc.perform(post("/users")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(signUpRequest)))
                .andExpect(status().isBadRequest())
                .andDo(print())
                .andReturn();
        String content = mvcResult.getResponse().getContentAsString();

        //then
        List<CommonExceptionAdvice.ValidationError> errors = JsonUtils.fromJson(content, new TypeToken<List<CommonExceptionAdvice.ValidationError>>(){}.getType());
        assertEquals(errors.size(), 3);

        errors.forEach(error -> {
            log.debug(error.getField());
            log.debug(error.getMessage());
        });
    }

    @Test
    @Transactional
    public void 회원가입_Pattern_Valid_테스트() throws Exception {
        //given
        SignUpRequest signUpRequest = SignUpRequest.builder().email("aaa").name("Changhee").password("aaaa").build();

        //when
        MvcResult mvcResult = mockMvc.perform(post("/users")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(signUpRequest)))
                .andExpect(status().isBadRequest())
                .andDo(print())
                .andReturn();

        //then
        String content = mvcResult.getResponse().getContentAsString();
        List<CommonExceptionAdvice.ValidationError> errors = JsonUtils.fromJson(content, new TypeToken<List<CommonExceptionAdvice.ValidationError>>(){}.getType());
        assertEquals(errors.size(), 2);

        errors.forEach(error -> {
            log.debug(error.getField());
            log.debug(error.getMessage());
        });
    }

    @Test
    @Transactional
    public void 로그인_유저_프로필_가져오기_테스트() throws Exception {

        //given
        User user = User.builder().name("Changhee").email("test@email.com").username("google_123456789").type(UserType.OAUTH).build();
        userRepository.save(user);
        OAuth2Account oAuth2Account = OAuth2Account.builder().provider("google").providerId("123456789").token("token").refreshToken("refresh_token").tokenExpiredAt(LocalDateTime.now().plusSeconds(3600)).build();
        oAuth2AccountRepository.save(oAuth2Account);
        user.linkSocial(oAuth2Account);

        String token = jwtProvider.generateToken(user.getUsername());
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
        assertEquals(userProfile.getName(), user.getName());
        assertEquals(userProfile.getEmail(), user.getEmail());
        assertEquals(userProfile.getAuthorities().get(0), AuthorityType.ROLE_MEMBER);
        assertEquals(userProfile.getSocialProvider(), "google");
    }

    @Test
    @Transactional
    public void 인증_토큰이_없을때_프로필_요청실패_테스트() throws Exception {

        MvcResult mvcResult = mockMvc.perform(get("/users/me"))
                .andExpect(status().isUnauthorized())
                .andDo(print()).andReturn();
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
        MvcResult mvcResult = mockMvc.perform(put("/users/me")
                .cookie(cookie).contentType(MediaType.APPLICATION_JSON_VALUE).content(JsonUtils.toJson(updateProfileRequest)))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        assertEquals(user.getName(), updateProfileRequest.getName());
        assertEquals(user.getEmail(), updateProfileRequest.getEmail());
        assertEquals(user.getUsername(), updateProfileRequest.getEmail());
    }

    @Test
    @Transactional
    public void 프로필_변경_validation_테스트() throws Exception{
        User user = User.builder().email("test@email.com").name("Changhee").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user);

        String token = jwtProvider.generateToken(user.getEmail());
        Cookie cookie = new Cookie("access_token", token);
        cookie.setMaxAge(60 * 3);
        cookie.setHttpOnly(true);
        cookie.setPath("/");

        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder().name("").email("test2email.com").build();
        MvcResult mvcResult = mockMvc.perform(put("/users/me")
                .cookie(cookie).contentType(MediaType.APPLICATION_JSON_VALUE).content(JsonUtils.toJson(updateProfileRequest)))
                .andExpect(status().isBadRequest())
                .andDo(print()).andReturn();

        String content = mvcResult.getResponse().getContentAsString();

        //then
        List<CommonExceptionAdvice.ValidationError> errors = JsonUtils.fromJson(content, new TypeToken<List<CommonExceptionAdvice.ValidationError>>(){}.getType());
        assertEquals(errors.size(), 2);

        errors.forEach(error -> {
            log.debug(error.getField());
            log.debug(error.getMessage());
        });
    }

    @Test
    @Transactional
    public void 인증_토큰이_없을때_프로필_변경요청_실패_테스트() throws Exception {
        User user = User.builder().email("test@email.com").name("Changhee").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user);

        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder().name("Updated name").email("test2@email.com").build();
        MvcResult mvcResult = mockMvc.perform(put("/users/me")
                .contentType(MediaType.APPLICATION_JSON_VALUE).content(JsonUtils.toJson(updateProfileRequest)))
                .andExpect(status().isUnauthorized())
                .andDo(print()).andReturn();
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
