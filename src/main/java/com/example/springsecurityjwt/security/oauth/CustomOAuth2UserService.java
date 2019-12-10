package com.example.springsecurityjwt.security.oauth;

import com.example.springsecurityjwt.oauth.*;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.users.User;
import com.example.springsecurityjwt.users.UserRepository;
import com.example.springsecurityjwt.users.UserType;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequestEntityConverter;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.Optional;

@Service
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";
    private static final ParameterizedTypeReference<Map<String, Object>> PARAMETERIZED_RESPONSE_TYPE =
            new ParameterizedTypeReference<Map<String, Object>>() {};

    private final UserRepository userRepository;
    private final OAuthAccountRepository oAuthAccountRepository;
    private final ObjectMapper objectMapper;
    private Converter<OAuth2UserRequest, RequestEntity<?>> requestEntityConverter = new OAuth2UserRequestEntityConverter();
    private RestOperations restOperations;

    public CustomOAuth2UserService(UserRepository userRepository, OAuthAccountRepository oAuthAccountRepository, ObjectMapper objectMapper) {
        this.userRepository = userRepository;
        this.oAuthAccountRepository = oAuthAccountRepository;
        this.objectMapper = objectMapper;
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        this.restOperations = restTemplate;
    }

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        RequestEntity<?> request = this.requestEntityConverter.convert(userRequest);

        ResponseEntity<Map<String, Object>> response;
        try {
            response = this.restOperations.exchange(request, PARAMETERIZED_RESPONSE_TYPE);
        } catch (OAuth2AuthorizationException ex) {
            OAuth2Error oauth2Error = ex.getError();
            StringBuilder errorDetails = new StringBuilder();
            errorDetails.append("Error details: [");
            errorDetails.append("UserInfo Uri: ").append(
                    userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri());
            errorDetails.append(", Error Code: ").append(oauth2Error.getErrorCode());
            if (oauth2Error.getDescription() != null) {
                errorDetails.append(", Error Description: ").append(oauth2Error.getDescription());
            }
            errorDetails.append("]");
            oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the UserInfo Resource: " + errorDetails.toString(), null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
        } catch (RestClientException ex) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the UserInfo Resource: " + ex.getMessage(), null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
        }

        Map<String, Object> userAttributes = response.getBody();

        try {
            log.debug("registrationId: {}", userRequest.getClientRegistration().getRegistrationId());
            return processOAuth2User(userRequest.getClientRegistration().getRegistrationId(), userAttributes);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(String registrationId, Map<String, Object> userAttributes) throws Exception{

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, userAttributes);
        Optional<OAuthAccount> optOAuthAccount = oAuthAccountRepository.findByProviderAndProviderId(OAuthProvider.valueOf(registrationId), oAuth2UserInfo.getId());
        User user = null;

        //해당 소셜 서비스 계정으로 처음 인증하는 경우 소셜 서비스 정보를 이용해 회원가입을 진행
        if (!optOAuthAccount.isPresent()) {
            log.debug("this oauth account is not exist");
            user = registerNewUser(oAuth2UserInfo);
            registerNewOAuthAccount(registrationId, oAuth2UserInfo, user);
            log.debug("create new account");
        }
        //해당 소셜 서비스 계정으로 인증된 계정이 있는 경우
        else {
            log.debug("this oauth account is exist");
            user = userRepository.findById(optOAuthAccount.get().getUserId()).get();
        }

        return CustomUserDetails.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .authorities(user.getAuthorities())
                .attributes(oAuth2UserInfo.getAttributes())
                .build();
    }

    private User registerNewUser(OAuth2UserInfo oAuth2UserInfo) {
        User user = User.builder()
                .name(oAuth2UserInfo.getName())
                .email(oAuth2UserInfo.getEmail())
                .type(UserType.OAUTH)
                .build();

        userRepository.save(user);
        return user;
    }

    private OAuthAccount registerNewOAuthAccount(String registrationId, OAuth2UserInfo oAuth2UserInfo, User user) {
        OAuthAccount oAuthAccount = OAuthAccount.builder()
                .userId(user.getId())
                .provider(OAuthProvider.valueOf(registrationId))
                .providerId(oAuth2UserInfo.getId())
                .build();

        oAuthAccountRepository.save(oAuthAccount);
        return oAuthAccount;
    }
}