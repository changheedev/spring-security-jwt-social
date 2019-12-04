package com.example.springsecurityjwt.security;


import com.example.springsecurityjwt.dto.UserDetailsDTO;
import com.example.springsecurityjwt.model.User;
import com.example.springsecurityjwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username);

        if(user == null)
            throw new UsernameNotFoundException("등록되지 않은 회원입니다.");

        UserDetailsDTO userDetailsDTO = new UserDetailsDTO().builder()
                .id(user.getId())
                .name(user.getName())
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getAuthorities())
                .build();

        return userDetailsDTO;
    }
}
