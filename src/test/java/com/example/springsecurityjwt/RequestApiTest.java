package com.example.springsecurityjwt;

import com.example.springsecurityjwt.dto.AuthenticationRequest;
import com.example.springsecurityjwt.dto.AuthenticationResponse;
import com.example.springsecurityjwt.dto.SignUpRequest;
import com.example.springsecurityjwt.model.User;
import com.example.springsecurityjwt.repository.UserRepository;
import com.example.springsecurityjwt.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class RequestApiTest {

    private final Logger log = LoggerFactory.getLogger(RequestApiTest.class);

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private UserService userService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    public void setup() {
        userRepository.deleteAll();
    }

    @Test
    @Transactional
    public void 회원가입_API_테스트() throws Exception{
        //given
        SignUpRequest signUpRequest = SignUpRequest.builder()
                .email("test@email.com")
                .name("ChangHee")
                .password("password")
                .build();

        //when
        MvcResult mvcResult = mockMvc.perform(post("/users")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isOk())
                .andReturn();

        //then
        User user = userRepository.findByEmail(signUpRequest.getEmail());
        assertNotNull(user);
    }

    @Test
    @Transactional
    public void 토큰_발급_API_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = SignUpRequest.builder()
                .email("test@email.com")
                .name("ChangHee")
                .password("password")
                .build();

        userService.signUpService(signUpRequest);

        AuthenticationRequest authenticationRequest = AuthenticationRequest.builder()
                .username(signUpRequest.getEmail())
                .password(signUpRequest.getPassword())
                .build();

        //when
        MvcResult mvcResult = mockMvc.perform(post("/authenticate")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsString(authenticationRequest)))
                .andExpect(status().isOk())
                .andReturn();

        //then
        String content = mvcResult.getResponse().getContentAsString();
        AuthenticationResponse authenticationResponse = objectMapper.readValue(content, AuthenticationResponse.class);

        log.debug("token : {}", authenticationResponse.getToken());
        log.debug("refresh token: {}", authenticationResponse.getRefreshToken());
        assertNotNull(authenticationResponse.getToken());
        assertNotNull(authenticationResponse.getRefreshToken());

    }

}
