package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.authentication.oauth2.ClientRegistration;
import com.example.springsecurityjwt.authentication.oauth2.ClientRegistrationRepository;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountDTO;
import com.example.springsecurityjwt.authentication.oauth2.service.OAuth2Service;
import com.example.springsecurityjwt.authentication.oauth2.service.OAuth2ServiceFactory;
import com.example.springsecurityjwt.security.AuthorityType;
import com.example.springsecurityjwt.security.UserDetailsImpl;
import com.example.springsecurityjwt.util.CookieUtils;
import com.example.springsecurityjwt.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/users/**")
public class UserController {

    private final UserService userService;
    private final RestTemplate restTemplate;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @PostMapping("")
    public ResponseEntity<?> signUpNewUser(@RequestBody @Valid SignUpRequest signUpRequest, BindingResult bindingResult){
        if(bindingResult.hasErrors()) throw new ValidationException("회원가입 유효성 검사 실패.", bindingResult.getFieldErrors());
        userService.saveUser(signUpRequest);
        return ResponseEntity.ok("Success");
    }

    @GetMapping("/me")
    public ResponseEntity<?> getAuthenticatedUserProfile(@AuthenticationPrincipal UserDetailsImpl loginUser) {
        log.debug("request user profile....");
        UserProfileResponse.UserProfileResponseBuilder userProfileResponseBuilder = UserProfileResponse.builder()
                .id(loginUser.getId())
                .name(loginUser.getName())
                .email(loginUser.getEmail())
                .authorities(loginUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).map(s -> AuthorityType.valueOf(s)).collect(Collectors.toList()));

        //연동된 소셜 계정이 존재하면 소셜 계정 정보 추가
        Optional<OAuth2AccountDTO> optionalOAuth2AccountDTO = userService.getOAuth2Account(loginUser.getUsername());
        if(optionalOAuth2AccountDTO.isPresent()) {
            OAuth2AccountDTO oAuth2AccountDTO = optionalOAuth2AccountDTO.get();
            userProfileResponseBuilder.socialProvider(oAuth2AccountDTO.getProvider()).linkedAt(oAuth2AccountDTO.getCreateAt());
        }
        return ResponseEntity.ok(userProfileResponseBuilder.build());
    }

    @PutMapping("/me")
    public void updateProfile(@RequestBody @Valid UpdateProfileRequest updateProfileRequest, BindingResult bindingResult, @AuthenticationPrincipal UserDetailsImpl loginUser) {
        if(bindingResult.hasErrors()) throw new ValidationException("프로필 업데이트 유효성 검사 실패", bindingResult.getFieldErrors());
        userService.updateProfile(loginUser.getUsername(), updateProfileRequest);
    }

    @DeleteMapping("/withdraw")
    public void withdrawUser(@AuthenticationPrincipal UserDetailsImpl loginUser, HttpServletRequest request, HttpServletResponse response) {
        Optional<OAuth2AccountDTO> optionalOAuth2AccountDTO = userService.withdrawUser(loginUser.getUsername());
        //연동된 소셜계정 정보가 있다면 연동해제 요청
        if(optionalOAuth2AccountDTO.isPresent()) {
            OAuth2AccountDTO oAuth2AccountDTO = optionalOAuth2AccountDTO.get();
            ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(oAuth2AccountDTO.getProvider());
            OAuth2Service oAuth2Service = OAuth2ServiceFactory.getOAuth2Service(restTemplate, oAuth2AccountDTO.getProvider());
            oAuth2Service.unlink(clientRegistration, oAuth2AccountDTO.getOAuth2Token());
        }
        CookieUtils.deleteAll(request, response);
    }
}
