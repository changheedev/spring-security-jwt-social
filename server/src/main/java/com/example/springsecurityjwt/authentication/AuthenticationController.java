package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.authentication.oauth2.*;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.jwt.JWT;
import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.util.CookieUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
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
    public ResponseEntity<?> authenticateUsernamePassword(@Valid @RequestBody AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {

        log.debug("login controller...");
        UserDetails userDetails = authenticationService.authenticateUsernamePassword(authorizationRequest.getUsername(), authorizationRequest.getPassword());
        return tokenResponseEntity(userDetails, authorizationRequest.getRedirectUri(), authorizationRequest.getResponseType(), response);
    }

    /* 토큰 쿠키를 삭제하고 refresh token 을 만료시키는 컨트롤러 (로그아웃) */
    @PostMapping("/authorize/logout")
    public ResponseEntity<?> expiredRefreshToken(@AuthenticationPrincipal UserDetails loginUser, HttpServletRequest request, HttpServletResponse response) {

        CookieUtils.deleteCookie(request, response, "access_token");
        authenticationService.expiredRefreshToken(loginUser.getUsername());
        return ResponseEntity.ok("success");
    }

    /**
     * 토큰을 갱신 해주는 컨트롤러
     * Cookie 토큰을 사용하는 경우 refresh token 을 지원하지 않는다.
     */
    @PostMapping("/authorize/refresh_token")
    public ResponseEntity<?> refreshAccessToken(@RequestBody RefreshTokenRequest refreshTokenRequest, HttpServletRequest request, HttpServletResponse response) {
        JWT token = authenticationService.refreshAccessToken(refreshTokenRequest.getToken(), refreshTokenRequest.getRefreshToken());
        return ResponseEntity.ok(token);
    }

    /* 사용자의 소셜 로그인 요청을 받아 각 소셜 서비스로 인증을 요청하는 컨트롤러 */
    @GetMapping("/oauth2/authorize/{provider}")
    public void redirectSocialAuthorizationPage(@PathVariable String provider, @RequestParam String redirectUri, HttpServletRequest request, HttpServletResponse response) throws Exception {

        log.debug("redirect to = {}", redirectUri);
        String state = UUID.randomUUID().toString().replace("-", "");

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);

        String authorizationUri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getAuthorizationUri())
                .queryParam("client_id", clientRegistration.getClientId())
                .queryParam("response_type", "code")
                .queryParam("include_granted_scopes", true)
                .queryParam("scope", String.join("+", clientRegistration.getScopes()))
                .queryParam("state", state)
                .queryParam("redirect_uri", redirectUri)
                .build().encode(StandardCharsets.UTF_8).toUriString();

        response.sendRedirect(authorizationUri);
    }

    /* 각 소셜 서비스로부터 인증 결과를 처리하는 컨트롤러 */
    @RequestMapping("/oauth2/callback/{provider}")
    public ResponseEntity<?> oAuth2AuthenticationCallback(@PathVariable String provider, @RequestBody OAuth2CallbackRequest callbackRequest, HttpServletRequest request, HttpServletResponse response, @AuthenticationPrincipal UserDetails loginUser) {

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);

        String accessToken = oAuth2AuthenticationService.getOAuth2AccessToken(OAuth2AccessTokenRequest.builder().clientRegistration(clientRegistration).code(callbackRequest.getCode()).state(callbackRequest.getState()).redirectUri(callbackRequest.getRedirectUri()).build());
        OAuth2UserInfo oAuth2UserInfo = oAuth2AuthenticationService.getOAuth2UserInfo(OAuth2UserInfoRequest.builder().clientRegistration(clientRegistration).accessToken(accessToken).build());

        //로그인 토큰이 있는 상태에서 인증하는 경우 (계정 연동) 콜백 처리
        if (loginUser != null) {
            oAuth2AuthenticationService.linkAccount(loginUser.getUsername(), provider, oAuth2UserInfo);
            AuthorizationResponse authorizationResponse = AuthorizationResponse.builder().redirectUri(callbackRequest.getRedirectUri()).authType("link").build();
            return ResponseEntity.ok(authorizationResponse);
        }
        //로그인 인증 콜백처리
        else {
            UserDetails userDetails = oAuth2AuthenticationService.loadUser(clientRegistration.getRegistrationId(), oAuth2UserInfo);
            return tokenResponseEntity(userDetails, callbackRequest.getRedirectUri(), callbackRequest.getResponseType(), response);
        }
    }

    private ResponseEntity<?> tokenResponseEntity(UserDetails userDetails, String redirectUri, String responseType, HttpServletResponse response) {

        AuthorizationResponse authorizationResponse = AuthorizationResponse.builder().authType("auth").redirectUri(redirectUri).build();

        //응답 타입이 쿠키인 경우 리프레쉬 토큰은 발급하지 않는다.
        if (responseType.equals("cookie")) {
            final int cookieMaxAge = jwtProvider.getProperties().getCookieExpired().intValue();

            //운영 환경인 경우 secure 옵션사용
            if (Arrays.stream(environment.getActiveProfiles()).anyMatch(profile -> profile.equalsIgnoreCase("prod")))
                CookieUtils.addCookie(response, "access_token", jwtProvider.generateCookieToken(userDetails.getUsername()), true, true, cookieMaxAge);
            else
                CookieUtils.addCookie(response, "access_token", jwtProvider.generateCookieToken(userDetails.getUsername()), true, false, cookieMaxAge);
            //토큰 만료시간 쿠키 추가
            CookieUtils.addCookie(response, "expires_in", String.valueOf(cookieMaxAge), cookieMaxAge);
        }
        //Response body 를 통해 토큰 발급
        else {
            JWT token = authenticationService.issueToken(userDetails.getUsername());
            authorizationResponse.setToken(token);
        }
        return ResponseEntity.ok(authorizationResponse);
    }
}
