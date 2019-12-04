package com.example.springsecurityjwt;

import com.example.springsecurityjwt.dto.SignUpRequest;
import com.example.springsecurityjwt.dto.UserDetailsDTO;
import com.example.springsecurityjwt.security.CustomUserDetailsService;
import com.example.springsecurityjwt.service.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
@SpringBootTest
public class UserServiceTest {

    @Autowired
    private UserService userService;
    @Autowired
    private CustomUserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @Transactional
    public void 회원가입서비스_테스트() {
        //given
        SignUpRequest signUpRequest = SignUpRequest.builder()
                .email("test@email.com")
                .name("ChangHee")
                .password("password")
                .build();

        //when
        userService.signUpService(signUpRequest);

        //then
        UserDetailsDTO userDetailsDTO = (UserDetailsDTO) userDetailsService.loadUserByUsername(signUpRequest.getEmail());

        assertEquals(userDetailsDTO.getName(), signUpRequest.getName());
        assertEquals(userDetailsDTO.getAuthorities().size(), 1);
        assertEquals(passwordEncoder.matches(signUpRequest.getPassword(), userDetailsDTO.getPassword()), true);
    }
}
