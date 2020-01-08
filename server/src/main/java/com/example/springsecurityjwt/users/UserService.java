package com.example.springsecurityjwt.users;

public interface UserService {
    void signUpService(SignUpRequest signUpRequest);
    UserProfileResponse getUserProfile(Long userId);
    void updateProfile(String username, UpdateProfileRequest updateProfileRequest);
}
