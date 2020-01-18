package com.example.springsecurityjwt.security;

import com.example.springsecurityjwt.SpringMvcTestSupport;
import com.example.springsecurityjwt.authentication.AuthorizationRequest;
import com.example.springsecurityjwt.users.User;
import com.example.springsecurityjwt.users.UserRepository;
import com.example.springsecurityjwt.users.UserType;
import com.example.springsecurityjwt.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.Cookie;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
public class SecurityTest extends SpringMvcTestSupport {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void CSRF_토큰_쿠키와_헤더가_존재할때_요청성공_테스트() throws Exception {

        User user = User.builder().email("test@email.com").name("테스트유저").username("test@email.com").type(UserType.DEFAULT).password(passwordEncoder.encode("password")).build();
        userRepository.save(user);

        mockMvc.perform(post("/authorize")
                .header("X-CSRF-TOKEN", CSRF_TOKEN)
                .cookie(new Cookie("CSRF-TOKEN", CSRF_TOKEN))
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(new AuthorizationRequest("test@email.com", "password"))))
                .andExpect(status().isOk()).andDo(print());
    }

    @Test
    public void CSRF_토큰_쿠키와_헤더가_존재하지_않을때_요청실패_테스트() throws Exception {

        User user = User.builder().email("test@email.com").name("테스트유저").username("test@email.com").type(UserType.DEFAULT).password(passwordEncoder.encode("password")).build();
        userRepository.save(user);

        mockMvc.perform(post("/authorize")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.toJson(new AuthorizationRequest("test@email.com", "password"))))
                .andExpect(status().isForbidden()).andDo(print());
    }
}
