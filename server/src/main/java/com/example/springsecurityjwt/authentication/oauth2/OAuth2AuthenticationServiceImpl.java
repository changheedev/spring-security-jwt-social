package com.example.springsecurityjwt.authentication.oauth2;

import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfoFactory;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.users.User;
import com.example.springsecurityjwt.users.UserRepository;
import com.example.springsecurityjwt.users.UserType;
import com.example.springsecurityjwt.util.JsonUtils;
import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class OAuth2AuthenticationServiceImpl implements OAuth2AuthenticationService {

    private final UserRepository userRepository;
    private final OAuth2AccountRepository oAuth2AccountRepository;
    private final RestTemplate restTemplate;

    @Override
    public String getOAuth2AccessToken(OAuth2AccessTokenRequest oAuth2AccessTokenRequest) {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        ClientRegistration clientRegistration = oAuth2AccessTokenRequest.getClientRegistration();

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", clientRegistration.getClientId());
        params.add("client_secret", clientRegistration.getClientSecret());
        params.add("grant_type", "authorization_code");
        params.add("code", oAuth2AccessTokenRequest.getCode());
        params.add("state", oAuth2AccessTokenRequest.getState());
        params.add("redirect_uri", oAuth2AccessTokenRequest.getRedirectUri());

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(params, headers);

        ResponseEntity<String> entity = restTemplate.exchange(clientRegistration.getProviderDetails().getTokenUri(), HttpMethod.POST, httpEntity, String.class);

        if (entity.getStatusCodeValue() != 200)
            throw new OAuth2AuthenticationFailedException(String.format("Get access token failed.\nProvider: %d, Code: %d \nDetails : %s", clientRegistration.getRegistrationId(), entity.getStatusCodeValue(), entity.getBody()));

        log.debug("Get access token result code (provider: {}) : {}", clientRegistration.getRegistrationId(), entity.getStatusCodeValue());
        JsonObject jsonObj = JsonUtils.parse(entity.getBody()).getAsJsonObject();
        String accessToken = jsonObj.get("access_token").getAsString();
        return accessToken;
    }

    @Override
    public OAuth2UserInfo getOAuth2UserInfo(OAuth2UserInfoRequest oAuth2UserInfoRequest) {

        ClientRegistration clientRegistration = oAuth2UserInfoRequest.getClientRegistration();

        HttpHeaders headers = new HttpHeaders();

        headers.add("Authorization", "Bearer " + oAuth2UserInfoRequest.getAccessToken());
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<?> httpEntity = new HttpEntity<>(headers);

        ResponseEntity<String> entity = restTemplate.exchange(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri(), HttpMethod.GET, httpEntity, String.class);

        if (entity.getStatusCodeValue() != 200)
            throw new OAuth2AuthenticationFailedException(String.format("Get access token failed.\nProvider: %d, Code: %d \nDetails : %s", clientRegistration.getRegistrationId(), entity.getStatusCodeValue(), entity.getBody()));

        Map<String, Object> userAttributes = JsonUtils.fromJson(entity.getBody(), Map.class);

        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(clientRegistration.getRegistrationId(), userAttributes);

        return userInfo;
    }

    @Override
    public boolean findOAuth2Account(String registrationId, String providerId) {
        return oAuth2AccountRepository.existsByProviderAndProviderId(registrationId, providerId);
    }

    @Override
    @Transactional
    public UserDetails loadUser(String registrationId, OAuth2UserInfo userInfo) {

        Optional<OAuth2Account> oAuth2Account = oAuth2AccountRepository.findByProviderAndProviderId(registrationId, userInfo.getId());
        User user = null;

        //가입된 계정이 존재할때
        if (oAuth2Account.isPresent()) {
            user = oAuth2Account.get().getUser();
        }
        //가입된 계정이 존재하지 않을때
        else {
            //이메일 정보가 있을때
            if (userInfo.getEmail() != null) {
                // 중복된 이메일을 사용하는 계정이 존재하는지 확인 후 있다면 소셜 계정과 연결시키고 없다면 새로 생성하여 연결 시킨다.
                user = userRepository.findByEmail(userInfo.getEmail())
                        .orElse(userRepository.save(User.builder()
                                .username(registrationId + "_" + userInfo.getId())
                                .name(userInfo.getName())
                                .email(userInfo.getEmail())
                                .type(UserType.OAUTH)
                                .build()));
            }
            //이메일 정보가 없을때
            else {
                user = userRepository.save(User.builder()
                        .username(registrationId + "_" + userInfo.getId())
                        .name(userInfo.getName())
                        .type(UserType.OAUTH)
                        .build());
            }

            OAuth2Account newAccount = OAuth2Account.builder().provider(registrationId).providerId(userInfo.getId()).user(user).build();
            oAuth2AccountRepository.save(newAccount);
        }

        CustomUserDetails userDetails = CustomUserDetails.builder().id(user.getId()).username(user.getUsername()).name(user.getName()).email(user.getEmail()).authorities(user.getAuthorities()).build();
        return userDetails;
    }

    @Override
    @Transactional
    public UserDetails linkAccount(String targetUsername, String registrationId, OAuth2UserInfo userInfo) {

        if (oAuth2AccountRepository.existsByProviderAndProviderId(registrationId, userInfo.getId()))
            throw new OAuth2LinkAccountFailedException("이미 연동된 계정입니다.");

        User user = userRepository.findByUsername(targetUsername)
                .orElseThrow(() -> new UsernameNotFoundException("찾을 수 없는 회원입니다."));

        OAuth2Account oAuth2Account = OAuth2Account.builder()
                .provider(registrationId)
                .providerId(userInfo.getId())
                .user(user)
                .build();

        oAuth2AccountRepository.save(oAuth2Account);

        return CustomUserDetails.builder().id(user.getId()).username(user.getUsername()).name(user.getName()).email(user.getEmail()).authorities(user.getAuthorities()).build();
    }
}
