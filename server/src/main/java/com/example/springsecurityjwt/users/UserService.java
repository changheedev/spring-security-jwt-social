package com.example.springsecurityjwt.users;

import java.util.Map;

public interface UserService {
    void signUpService(SignUpRequest signUpRequest);
    Map<String, Object> getLinkedSocialAccountMap(String username);
    void updateProfile(String username, UpdateProfileRequest updateProfileRequest);
}
