package com.example.springsecurityjwt.authentication;

import org.springframework.security.core.userdetails.UserDetails;

public interface AuthenticationService {

    UserDetails authenticateUsernamePassword(String username, String password);
}
