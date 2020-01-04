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
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
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
    private final InMemoryOAuth2RequestRepository inMemoryOAuth2RequestRepository;
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
    public void redirectSocialAuthorizationPage(@PathVariable String provider, @RequestParam(name = "redirect_uri") String redirectUri, @RequestParam String callback, HttpServletRequest request, HttpServletResponse response) throws Exception {

        String state = UUID.randomUUID().toString().replace("-", "");

        // 콜백에서 사용할 요청 정보를 저장
        inMemoryOAuth2RequestRepository.saveOAuth2Request(state, OAuth2AuthorizationRequest.builder().referer(request.getHeader("referer")).redirectUri(redirectUri).callback(callback).build());

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);

        String authorizationUri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getAuthorizationUri())
                .queryParam("client_id", clientRegistration.getClientId())
                .queryParam("response_type", "code")
                .queryParam("include_granted_scopes", true)
                .queryParam("scope", String.join("+", clientRegistration.getScopes()))
                .queryParam("state", state)
                .queryParam("redirect_uri", clientRegistration.getRedirectUri())
                .build().encode(StandardCharsets.UTF_8).toUriString();

        response.sendRedirect(authorizationUri);
    }

    /* 각 소셜 서비스로부터 인증 결과를 처리하는 컨트롤러 */
    @RequestMapping("/oauth2/callback/{provider}")
    public void oAuth2AuthenticationCallback(@PathVariable String provider, OAuth2AuthorizationResponse oAuth2AuthorizationResponse, HttpServletRequest request, HttpServletResponse response, @AuthenticationPrincipal CustomUserDetails loginUser) throws Exception {

        //인증을 요청할 때 저장했던 request 정보를 가져온다.
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = inMemoryOAuth2RequestRepository.deleteOAuth2Request(oAuth2AuthorizationResponse.getState());

        //유저가 로그인 페이지에서 로그인을 취소하거나 오류가 발생했을때 처리
        if (oAuth2AuthorizationResponse.getError() != null) {
            String redirectUri = UriComponentsBuilder.fromUriString(oAuth2AuthorizationRequest.getReferer())
                    .queryParam("error", oAuth2AuthorizationResponse.getError()).encode().build().toUriString();
            response.sendRedirect(redirectUri);
            return;
        }

        UriComponentsBuilder redirectUriBuilder = UriComponentsBuilder.fromUriString(oAuth2AuthorizationRequest.getRedirectUri());

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);
        String accessToken = oAuth2AuthenticationService.getOAuth2AccessToken(clientRegistration, oAuth2AuthorizationResponse.getCode(), oAuth2AuthorizationResponse.getState());
        OAuth2UserInfo oAuth2UserInfo = oAuth2AuthenticationService.getOAuth2UserInfo(clientRegistration, accessToken);
        //로그인에 대한 콜백 처리
        if (oAuth2AuthorizationRequest.getCallback().equalsIgnoreCase("login")) {
            UserDetails userDetails = oAuth2AuthenticationService.loadUser(provider, oAuth2UserInfo);
            createTokenCookie(userDetails, response);
        }
        //계정 연동에 대한 콜백 처리
        else if (oAuth2AuthorizationRequest.getCallback().equalsIgnoreCase("link")) {
            //로그인 상태가 아니면
            if (loginUser == null)
                throw new UnauthorizedException("Access token is required to link social oauth");

            try {
                oAuth2AuthenticationService.linkAccount(loginUser.getUsername(), provider, oAuth2UserInfo);
            } catch (OAuth2ProcessException e) {
                redirectUriBuilder.queryParam("error", true);
                redirectUriBuilder.queryParam("message", e.getMessage());
            }
        }
        //계정 연동 해제에 대한 콜백 처리
        else if (oAuth2AuthorizationRequest.getCallback().equalsIgnoreCase("unlink")) {
            //로그인 상태가 아니면
            if (loginUser == null)
                throw new UnauthorizedException("Access token is required to unlink social oauth");
            oAuth2AuthenticationService.unlinkAccount(clientRegistration, accessToken, oAuth2UserInfo, loginUser.getId());
        } else throw new OAuth2ProcessException("This callback not supported");

        redirectUriBuilder.encode().build();
        log.debug("social authentication success, redirect to {}", redirectUriBuilder.toUriString());
        response.sendRedirect(redirectUriBuilder.toUriString());
    }

    private void createTokenCookie(UserDetails userDetails, HttpServletResponse response) throws IOException {
        final int cookieMaxAge = jwtProvider.getTokenExpirationDate().intValue();

        //운영 환경인 경우 secure 옵션사용
        if (Arrays.stream(environment.getActiveProfiles()).anyMatch(profile -> profile.equalsIgnoreCase("prod"))) {
            CookieUtils.addCookie(response, "access_token", jwtProvider.generateToken(userDetails.getUsername()), true, true, cookieMaxAge);
            CookieUtils.addCookie(response, "logged_name", URLEncoder.encode(((CustomUserDetails) userDetails).getName(), "utf-8"), true, true, cookieMaxAge);
        } else {
            CookieUtils.addCookie(response, "access_token", jwtProvider.generateToken(userDetails.getUsername()), true, false, cookieMaxAge);
            CookieUtils.addCookie(response, "logged_name", URLEncoder.encode(((CustomUserDetails) userDetails).getName(), "utf-8"), true, false, cookieMaxAge);
        }
    }

    private void removeTokenCookie(HttpServletRequest request, HttpServletResponse response) {
        CookieUtils.deleteCookie(request, response, "access_token");
        CookieUtils.deleteCookie(request, response, "logged_name");
    }


    @GetMapping("/test")
    public void testContoller() {

    }
}
