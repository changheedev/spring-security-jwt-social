package com.example.springsecurityjwt.users;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void signUpService(SignUpRequest signUpRequest) {

        if(userRepository.findByUsername(signUpRequest.getEmail()).isPresent())
            throw new DuplicatedUsernameException("이미 가입된 이메일입니다.");

        User user = User.builder()
                .username(signUpRequest.getEmail())
                .name(signUpRequest.getName())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .type(UserType.DEFAULT)
                .build();

        userRepository.save(user);
    }
}
