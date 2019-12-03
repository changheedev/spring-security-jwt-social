package com.example.springsecurityjwt.repository;

import com.example.springsecurityjwt.model.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
public class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    @Transactional
    public void insertUserTest(){
        User user = new User("charvi", "abc@email.com", "password");
        userRepository.save(user);
    }
}
