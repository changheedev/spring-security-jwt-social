package com.example.springsecurityjwt.users;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/users")
    public ResponseEntity<?> signUpNewUser(@RequestBody SignUpRequest signUpRequest) throws Exception{
        userService.signUpService(signUpRequest);
        return ResponseEntity.ok("Success");
    }

}
