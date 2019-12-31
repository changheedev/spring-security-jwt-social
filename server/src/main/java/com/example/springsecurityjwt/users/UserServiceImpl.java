package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZoneId;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final OAuth2AccountRepository oAuth2AccountRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void signUpService(SignUpRequest signUpRequest) {

        if (userRepository.findByUsername(signUpRequest.getEmail()).isPresent())
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

    @Override
    public Map<String, Object> getLinkedSocialAccountMap(String username) {

        Map<String, Object> resultMap = new HashMap<>();
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isPresent()) {
            List<OAuth2Account> accounts = oAuth2AccountRepository.findAllByUser(user.get());
            // (provider, milli seconds 포맷의 연동시간) 쌍으로 데이터를 저장
            accounts.forEach(account -> resultMap.put(account.getProvider(), String.valueOf(account.getCreateAt().atZone(ZoneId.systemDefault()).toInstant().toEpochMilli())));
        }
        return resultMap;
    }

    @Override
    @Transactional
    public void updateProfile(String username, UpdateProfileRequest updateProfileRequest) {

        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("등록되지 않은 회원입니다."));

        //이름이 변경되었는지 체크
        if (!user.getName().equals(updateProfileRequest.getName()))
            user.updateName(updateProfileRequest.getName());

        //이메일이 변경되었는지 체크
        if (!user.getEmail().equals(updateProfileRequest.getEmail())) {
            if (userRepository.existsByEmail(updateProfileRequest.getEmail()))
                throw new DuplicatedUsernameException("사용할 수 없는 이메일 입니다.");
            user.updateEmail(updateProfileRequest.getEmail());
        }
    }
}
