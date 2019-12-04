package com.example.springsecurityjwt.service;

import com.example.springsecurityjwt.dto.SignUpRequest;
import com.example.springsecurityjwt.model.User;
import com.example.springsecurityjwt.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void signUpService(SignUpRequest signUpRequest) {

        if(userRepository.findByEmail(signUpRequest.getEmail()) != null)
            throw new DuplicatedUsernameException("이미 가입된 이메일입니다.");

        User user = User.builder()
                .email(signUpRequest.getEmail())
                .name(signUpRequest.getName())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .build();

        userRepository.save(user);
    }
}
