package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.security.AuthorityType;
import com.example.springsecurityjwt.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.stream.Collectors;

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
        UserProfileResponse userProfile = UserProfileResponse.builder()
                .id(loginUser.getId())
                .name(loginUser.getName())
                .email(loginUser.getEmail())
                .authorities(loginUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).map(s -> AuthorityType.valueOf(s)).collect(Collectors.toList()))
                .build();
        return ResponseEntity.ok(userProfile);
    }

    @GetMapping("/social")
    public ResponseEntity<?> getLinkedSocialAccountInfo(@AuthenticationPrincipal CustomUserDetails loginUser) {

        Map<String, Object> linkedAccountMap = userService.getLinkedSocialAccountMap(loginUser.getUsername());
        return ResponseEntity.ok(linkedAccountMap);
    }

    @PutMapping("")
    public void updateProfile(@RequestBody UpdateProfileRequest updateProfileRequest, @AuthenticationPrincipal CustomUserDetails loginUser) {
        userService.updateProfile(loginUser.getUsername(), updateProfileRequest);
    }
}
