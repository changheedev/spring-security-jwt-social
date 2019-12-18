package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.users.SignUpRequest;
import com.example.springsecurityjwt.security.CustomUserDetailsService;
import com.example.springsecurityjwt.users.UserService;
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
        CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(signUpRequest.getEmail());

        assertEquals(userDetails.getName(), signUpRequest.getName());
        assertEquals(userDetails.getAuthorities().size(), 1);
        assertEquals(passwordEncoder.matches(signUpRequest.getPassword(), userDetails.getPassword()), true);
    }
}
