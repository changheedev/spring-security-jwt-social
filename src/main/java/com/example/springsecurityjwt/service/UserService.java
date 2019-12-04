package com.example.springsecurityjwt.service;

import com.example.springsecurityjwt.dto.SignUpRequest;

public interface UserService {
    void signUpService(SignUpRequest signUpRequest);
}
