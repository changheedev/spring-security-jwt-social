package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/users/**")
public class UserController {

    private final UserService userService;

    @PostMapping("")
    public ResponseEntity<?> signUpNewUser(@RequestBody SignUpRequest signUpRequest) throws Exception {
        userService.signUpService(signUpRequest);
        return ResponseEntity.ok("Success");
    }

    @GetMapping("/me")
    public ResponseEntity<?> getAuthenticatedUserProfile(@AuthenticationPrincipal CustomUserDetails loginUser) {
        log.debug("request user profile....");
        UserProfileResponse userProfile = userService.getUserProfile(loginUser.getId());
        return ResponseEntity.ok(userProfile);
    }

    @PutMapping("")
    public void updateProfile(@RequestBody UpdateProfileRequest updateProfileRequest, @AuthenticationPrincipal CustomUserDetails loginUser) {
        userService.updateProfile(loginUser.getUsername(), updateProfileRequest);
    }

    @DeleteMapping("")
    public void withdrawUser(@AuthenticationPrincipal CustomUserDetails loginUser) {

    }
}
