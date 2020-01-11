package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.SpringTestSupport;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

public class UserRepositoryTest extends SpringTestSupport {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @Transactional
    public void insertUserTest() {
        User user = User.builder()
                .username("test@email.com")
                .name("changhee")
                .email("test@email.com")
                .password(passwordEncoder.encode("password"))
                .type(UserType.DEFAULT)
                .build();
        userRepository.save(user);
    }
}
