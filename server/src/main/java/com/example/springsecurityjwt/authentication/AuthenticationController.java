package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.authentication.oauth2.OAuth2AccessTokenRequest;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2AuthenticationService;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2LinkAccountFailedException;
import com.example.springsecurityjwt.authentication.oauth2.OAuth2UserInfoRequest;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.util.CookieUtils;
import com.example.springsecurityjwt.util.JsonUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final OAuth2AuthenticationService oAuth2AuthenticationService;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final JwtProvider jwtProvider;
    private final Environment environment;

    /* 사용자의 계정을 인증하고 로그인 토큰을 발급해주는 컨트롤러 */
    @PostMapping("/authorize")
    public void authenticateUsernamePassword(@Valid @RequestBody AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) throws IOException {

        log.debug("login controller...");
        UserDetails userDetails = authenticationService.authenticateUsernamePassword(authorizationRequest.getUsername(), authorizationRequest.getPassword());
        createTokenCookie(userDetails, response);
    }

    /* 토큰 쿠키를 삭제하는 컨트롤러 (로그아웃) */
    @PostMapping("/authorize/logout")
    public ResponseEntity<?> expiredRefreshToken(@AuthenticationPrincipal UserDetails loginUser, HttpServletRequest request, HttpServletResponse response) {

        removeTokenCookie(request, response);
        return ResponseEntity.ok("success");
    }

    /* 사용자의 소셜 로그인 요청을 받아 각 소셜 서비스로 인증을 요청하는 컨트롤러 */
    @GetMapping("/oauth2/authorize/{provider}")
    public void redirectSocialAuthorizationPage(@PathVariable String provider, @RequestParam(name = "redirect_uri") String redirectUri, HttpServletRequest request, HttpServletResponse response) throws Exception {

        CookieUtils.addCookie(response, "redirect_uri", redirectUri, true, false, 180);

        String state = UUID.randomUUID().toString().replace("-", "");

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);

        String authorizationUri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getAuthorizationUri())
                .queryParam("client_id", clientRegistration.getClientId())
                .queryParam("response_type", "code")
                .queryParam("include_granted_scopes", true)
                .queryParam("scope", String.join("+", clientRegistration.getScopes()))
                .queryParam("state", state)
                .queryParam("redirect_uri", expandRedirectUri(request, clientRegistration))
                .build().encode(StandardCharsets.UTF_8).toUriString();

        response.sendRedirect(authorizationUri);
    }

    /* 각 소셜 서비스로부터 인증 결과를 처리하는 컨트롤러 */
    @RequestMapping("/oauth2/callback/{provider}")
    public void oAuth2AuthenticationCallback(@PathVariable String provider, OAuth2AuthorizationResponse oAuth2AuthorizationResponse, HttpServletRequest request, HttpServletResponse response, @AuthenticationPrincipal UserDetails loginUser) throws Exception {

        log.debug("callback....\n{}", JsonUtils.toJson(oAuth2AuthorizationResponse));
        UriComponentsBuilder redirectUriBuilder = UriComponentsBuilder.fromUriString(CookieUtils.getCookie(request, "redirect_uri").map(Cookie::getValue).get());
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);

        String accessToken = oAuth2AuthenticationService.getOAuth2AccessToken(OAuth2AccessTokenRequest.builder().clientRegistration(clientRegistration).code(oAuth2AuthorizationResponse.getCode()).state(oAuth2AuthorizationResponse.getState()).redirectUri(expandRedirectUri(request, clientRegistration)).build());
        OAuth2UserInfo oAuth2UserInfo = oAuth2AuthenticationService.getOAuth2UserInfo(OAuth2UserInfoRequest.builder().clientRegistration(clientRegistration).accessToken(accessToken).build());

        //로그인 토큰이 있는 상태에서 인증하는 경우 (계정 연동) 콜백 처리
        if (loginUser != null) {
            try {
                oAuth2AuthenticationService.linkAccount(loginUser.getUsername(), provider, oAuth2UserInfo);
            } catch (OAuth2LinkAccountFailedException e) {
                redirectUriBuilder.queryParam("error", true);
                redirectUriBuilder.queryParam("message", e.getMessage());
            }
        }
        //로그인 인증 콜백처리
        else {
            UserDetails userDetails = oAuth2AuthenticationService.loadUser(clientRegistration.getRegistrationId(), oAuth2UserInfo);
            createTokenCookie(userDetails, response);
        }

        redirectUriBuilder.encode().build();
        log.debug("social authentication success, redirect to {}", redirectUriBuilder.toUriString());
        CookieUtils.deleteCookie(request, response, "redirect_uri");
        response.sendRedirect(redirectUriBuilder.toUriString());
    }

    private void createTokenCookie(UserDetails userDetails, HttpServletResponse response) throws IOException {
        final int cookieMaxAge = jwtProvider.getTokenExpirationDate().intValue();

        //운영 환경인 경우 secure 옵션사용
        if (Arrays.stream(environment.getActiveProfiles()).anyMatch(profile -> profile.equalsIgnoreCase("prod"))) {
            CookieUtils.addCookie(response, "access_token", jwtProvider.generateToken(userDetails.getUsername()), true, true, cookieMaxAge);
            CookieUtils.addCookie(response, "logged_name", URLEncoder.encode(((CustomUserDetails) userDetails).getName(), "utf-8"), true, true, cookieMaxAge);
        }
        else{
            CookieUtils.addCookie(response, "access_token", jwtProvider.generateToken(userDetails.getUsername()), true, false, cookieMaxAge);
            CookieUtils.addCookie(response, "logged_name", URLEncoder.encode(((CustomUserDetails) userDetails).getName(), "utf-8"), true, false, cookieMaxAge);
        }
    }

    private void removeTokenCookie(HttpServletRequest request, HttpServletResponse response) {
        CookieUtils.deleteCookie(request, response, "access_token");
        CookieUtils.deleteCookie(request, response, "logged_name");
    }

    /* RedirectUriTemplate 을 이용해 RedirectUri 를 완성시켜주는 메소드 */
    private String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration) {
        Map<String, String> uriVariables = new HashMap<>();
        uriVariables.put("registrationId", clientRegistration.getRegistrationId());

        UriComponents uriComponents = UriComponentsBuilder.fromUriString(request.getRequestURL().toString())
                .replacePath(request.getContextPath())
                .replaceQuery(null)
                .fragment(null)
                .build();

        uriVariables.put("baseUrl", uriComponents.toUriString());

        return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate())
                .buildAndExpand(uriVariables)
                .toUriString();
    }
}
