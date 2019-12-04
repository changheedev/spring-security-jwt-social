package com.example.springsecurityjwt;

import com.example.springsecurityjwt.model.User;
import com.example.springsecurityjwt.repository.UserRepository;
import com.example.springsecurityjwt.util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

@ExtendWith(SpringExtension.class)
@SpringBootTest
public class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Test
    @Transactional
    public void insertUserTest(){
        User user = new User("charvi", "abc@email.com", "password");
        userRepository.save(user);
    }
}
