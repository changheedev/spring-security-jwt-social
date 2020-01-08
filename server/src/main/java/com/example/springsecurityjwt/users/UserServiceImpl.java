package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.security.AuthorityType;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final OAuth2AccountRepository oAuth2AccountRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void signUpService(SignUpRequest signUpRequest) {

        if (userRepository.findByUsername(signUpRequest.getEmail()).isPresent())
            throw new DuplicatedUsernameException("This is a registered member");

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
    @Transactional(readOnly = true)
    public UserProfileResponse getUserProfile(Long userId) {
        User user = userRepository.findById(userId).get();
        UserProfileResponse.UserProfileResponseBuilder userProfileResponseBuilder = UserProfileResponse.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .authorities(user.getAuthorities().stream().map(GrantedAuthority::getAuthority).map(s -> AuthorityType.valueOf(s)).collect(Collectors.toList()));

        //연동된 소셜 계정이 존재하면 소셜 계정 정보 추가
        Optional<OAuth2Account> optionalOAuth2Account = oAuth2AccountRepository.findByUser(user);
        if(optionalOAuth2Account.isPresent()) {
            OAuth2Account oAuth2Account = optionalOAuth2Account.get();
            userProfileResponseBuilder.socialProvider(oAuth2Account.getProvider()).linkedAt(oAuth2Account.getCreateAt());
        }

        return userProfileResponseBuilder.build();
    }

    @Override
    @Transactional
    public void updateProfile(String username, UpdateProfileRequest updateProfileRequest) {

        User user = userRepository.findByUsername(username).get();

        //이름이 변경되었는지 체크
        if (!user.getName().equals(updateProfileRequest.getName()))
            user.updateName(updateProfileRequest.getName());

        //이메일이 변경되었는지 체크
        if (!user.getEmail().equals(updateProfileRequest.getEmail())) {
            if (userRepository.existsByEmail(updateProfileRequest.getEmail()))
                throw new DuplicatedUsernameException("This email is already in use");
            user.updateEmail(updateProfileRequest.getEmail());
        }
    }
}
