package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.SpringMvcTestSupport;
import com.example.springsecurityjwt.advice.CommonExceptionAdvice;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.security.AuthorityType;
import com.example.springsecurityjwt.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.Cookie;
import java.time.LocalDateTime;
import java.util.Optional;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
public class UsersApiTest extends SpringMvcTestSupport {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private OAuth2AccountRepository oAuth2AccountRepository;
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void 회원가입_API_테스트() throws Exception {
        //given
        String email = "test@email.com";
        String name = "ChangHee";
        String password = "password";

        //when
        SignUpRequest signUpRequest = registerTestUser(email, name, password);

        //then
        Optional<User> user = userRepository.findByUsername(signUpRequest.getEmail());
        assertTrue(user.isPresent(), "유저 정보가 정삭적으로 저장되지 않음");
    }

    @Test
    public void 중복된_이메일로_회원가입_요청시_실패_테스트() throws Exception {
        //given
        User user = User.builder().name("Changhee").email("test@email.com").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user);
        SignUpRequest signUpRequest = SignUpRequest.builder().email("test@email.com").name("new User").password("password").build();

        //when
        MvcResult mvcResult = mockMvc.perform(post("/users")
                .header("X-CSRF-TOKEN", CSRF_TOKEN)
                .cookie(new Cookie("CSRF-TOKEN", CSRF_TOKEN))
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(signUpRequest)))
                .andExpect(status().isBadRequest())
                .andDo(print())
                .andReturn();

        //then
        String content = mvcResult.getResponse().getContentAsString();
        CommonExceptionAdvice.ErrorResponse errorResponse = JsonUtils.fromJson(content, CommonExceptionAdvice.ErrorResponse.class);
        assertEquals(1, errorResponse.getErrors().size(), "이메일 중복 검사가 정상적으로 진행되지 않음");
        assertEquals("email", errorResponse.getErrors().get(0).getField(), "이메일 중복 검사가 정상적으로 진행되지 않음");
    }


    @Test
    public void 회원가입_Null_Valid_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = SignUpRequest.builder().email("").name("").password("").build();

        //when
        MvcResult mvcResult = mockMvc.perform(post("/users")
                .header("X-CSRF-TOKEN", CSRF_TOKEN)
                .cookie(new Cookie("CSRF-TOKEN", CSRF_TOKEN))
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(signUpRequest)))
                .andExpect(status().isBadRequest())
                .andDo(print())
                .andReturn();
        String content = mvcResult.getResponse().getContentAsString();

        //then
        CommonExceptionAdvice.ErrorResponse errorResponse = JsonUtils.fromJson(content, CommonExceptionAdvice.ErrorResponse.class);
        assertEquals(3, errorResponse.getErrors().size(), "이메일, 이름, 패스워드의 Null 유효성 검사가 정상적으로 진행되지 않음");

        errorResponse.getErrors().forEach(error -> {
            log.debug(error.getField());
            log.debug(error.getDefaultMessage());
        });
    }

    @Test
    public void 회원가입_Pattern_Valid_테스트() throws Exception {
        //given
        SignUpRequest signUpRequest = SignUpRequest.builder().email("aaa").name("Changhee").password("aaaa").build();

        //when
        MvcResult mvcResult = mockMvc.perform(post("/users")
                .header("X-CSRF-TOKEN", CSRF_TOKEN)
                .cookie(new Cookie("CSRF-TOKEN", CSRF_TOKEN))
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(signUpRequest)))
                .andExpect(status().isBadRequest())
                .andDo(print())
                .andReturn();

        //then
        String content = mvcResult.getResponse().getContentAsString();
        CommonExceptionAdvice.ErrorResponse errorResponse = JsonUtils.fromJson(content, CommonExceptionAdvice.ErrorResponse.class);
        assertEquals(2, errorResponse.getErrors().size(), "이메일, 패스워드의 Pattern 유효성 검사가 정상적으로 진행되지 않음");

        errorResponse.getErrors().forEach(error -> {
            log.debug(error.getField());
            log.debug(error.getDefaultMessage());
        });
    }

    @Test
    public void 회원탈퇴_테스트() throws Exception{
        //given
        User user = User.builder().email("test@email.com").name("Changhee").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user);

        String token = jwtProvider.generateToken(user.getUsername());
        Cookie cookie = new Cookie("access_token", token);
        cookie.setMaxAge(60 * 3);
        cookie.setHttpOnly(true);
        cookie.setPath("/");

        //when
        MvcResult mvcResult = mockMvc.perform(delete("/users/withdraw")
                .header("X-CSRF-TOKEN", CSRF_TOKEN)
                .cookie(new Cookie("CSRF-TOKEN", CSRF_TOKEN))
                .cookie(cookie))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        //then
        assertFalse(userRepository.existsByUsername("test@email.com"), "회원 탈퇴 후 회원 정보가 삭제되지 않음");
    }


    @Test
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

        assertNotNull(userProfile, "유저 프로필 정보를 가져오는데 실패");
        assertEquals(user.getName(), userProfile.getName(), "프로필의 이름 정보가 유저의 이름과 다름");
        assertEquals(user.getEmail(), userProfile.getEmail(), "프로필의 이메일 정보가 유저의 이메일과 다름");
        assertEquals(AuthorityType.ROLE_MEMBER, userProfile.getAuthorities().get(0), "권한 정보가 저장되지 않음");
        assertEquals("google", userProfile.getSocialProvider(), "연동된 소셜 계정 정보가 저장되지 않음");
    }

    @Test
    public void 인증_토큰이_없을때_프로필_요청실패_테스트() throws Exception {

        MvcResult mvcResult = mockMvc.perform(get("/users/me"))
                .andExpect(status().isUnauthorized())
                .andDo(print()).andReturn();
    }

    @Test
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
                .header("X-CSRF-TOKEN", CSRF_TOKEN)
                .cookie(new Cookie("CSRF-TOKEN", CSRF_TOKEN))
                .cookie(cookie).contentType(MediaType.APPLICATION_JSON_VALUE).content(JsonUtils.toJson(updateProfileRequest)))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        assertEquals(user.getName(), updateProfileRequest.getName(), "이름이 업데이트 되지 않음");
        assertEquals(user.getEmail(), updateProfileRequest.getEmail(), "이메일이 업데이트 되지 않음");
        assertEquals(user.getUsername(), updateProfileRequest.getEmail(), "username 이 함께 업데이트 되지 않음");
    }

    @Test
    public void 프로필_변경_validation_테스트() throws Exception {
        User user = User.builder().email("test@email.com").name("Changhee").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user);

        String token = jwtProvider.generateToken(user.getEmail());
        Cookie cookie = new Cookie("access_token", token);
        cookie.setMaxAge(60 * 3);
        cookie.setHttpOnly(true);
        cookie.setPath("/");

        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder().name("").email("test2email.com").build();
        MvcResult mvcResult = mockMvc.perform(put("/users/me")
                .header("X-CSRF-TOKEN", CSRF_TOKEN)
                .cookie(new Cookie("CSRF-TOKEN", CSRF_TOKEN))
                .cookie(cookie).contentType(MediaType.APPLICATION_JSON_VALUE).content(JsonUtils.toJson(updateProfileRequest)))
                .andExpect(status().isBadRequest())
                .andDo(print()).andReturn();

        String content = mvcResult.getResponse().getContentAsString();

        //then
        CommonExceptionAdvice.ErrorResponse errorResponse = JsonUtils.fromJson(content, CommonExceptionAdvice.ErrorResponse.class);
        assertEquals(2, errorResponse.getErrors().size(), "이름의 Null 유효성과 이메일 패턴 유효성 검사가 정상적으로 진행되지 않음");

        errorResponse.getErrors().forEach(error -> {
            log.debug(error.getField());
            log.debug(error.getDefaultMessage());
        });
    }

    @Test
    public void 인증_토큰이_없을때_프로필_변경요청_실패_테스트() throws Exception {
        User user = User.builder().email("test@email.com").name("Changhee").username("test@email.com").password(passwordEncoder.encode("password")).type(UserType.DEFAULT).build();
        userRepository.save(user);

        UpdateProfileRequest updateProfileRequest = UpdateProfileRequest.builder().name("Updated name").email("test2@email.com").build();
        MvcResult mvcResult = mockMvc.perform(put("/users/me")
                .header("X-CSRF-TOKEN", CSRF_TOKEN)
                .cookie(new Cookie("CSRF-TOKEN", CSRF_TOKEN))
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
                .header("X-CSRF-TOKEN", CSRF_TOKEN)
                .cookie(new Cookie("CSRF-TOKEN", CSRF_TOKEN))
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(signUpRequest)))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn();
    }
}
