package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.authentication.oauth2.*;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
import java.util.UUID;

@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final OAuth2AuthenticationService oAuth2AuthenticationService;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final JwtProvider jwtProvider;

    /* 사용자의 계정을 인증하고 로그인 토큰을 발급해주는 컨트롤러 */
    @PostMapping("/authorize")
    public ResponseEntity<?> authenticateUsernamePassword(@Valid @RequestBody AuthenticationRequest authenticationRequest) {
        UserDetails userDetails = authenticationService.authenticateUsernamePassword(authenticationRequest.getUsername(), authenticationRequest.getPassword());
        return ResponseEntity.ok(authenticationService.issueAccessToken(userDetails));
    }

    /* 토큰을 갱신 해주는 컨트롤러 */
    @PostMapping("/authorize/refresh_token")
    public ResponseEntity<?> refreshAccessToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        AccessTokenResponse accessTokenResponse = authenticationService.refreshAccessToken(refreshTokenRequest.getRefreshToken());
        return ResponseEntity.ok(accessTokenResponse);
    }

    /* 유저의 refresh token 을 만료시키는 컨트롤러 (로그아웃) */
    @DeleteMapping("/authorize/refresh_token")
    public ResponseEntity<?> expiredRefreshToken(@AuthenticationPrincipal CustomUserDetails userDetails){

        authenticationService.expiredRefreshToken(userDetails.getUsername());
        return ResponseEntity.ok("success");
    }

    /* 사용자의 소셜 로그인 요청을 받아 각 소셜 서비스로 인증을 요청하는 컨트롤러 */
    @GetMapping("/oauth2/authorize/{provider}")
    public void redirectSocialAuthorizationPage(@PathVariable String provider, @RequestParam String redirectUri, HttpServletRequest request, HttpServletResponse response) throws Exception {

        if(!isAuthorizedRedirectUri(requestParams.getRedirectUri()))
            throw new AuthenticationFailedException("허가되지 않은 리디렉션 URI 입니다.");

        CookieUtils.addCookie(response, OAUTH2_AUTHORIZATION_COOKIE_NAME, URLEncoder.encode(JsonUtils.toJson(requestParams),"utf-8"), 180);

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
    public ResponseEntity<?> oAuth2AuthenticationCallback(@PathVariable String provider, OAuth2CallbackRequest callbackRequest, HttpServletRequest request) {

        final String authorizationHeader = request.getHeader("Authorization");
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);

        String accessToken = oAuth2AuthenticationService.getOAuth2AccessToken(OAuth2AccessTokenRequest.builder().clientRegistration(clientRegistration).code(callbackRequest.getCode()).state(callbackRequest.getState()).redirectUri(callbackRequest.getRedirectUri()).build());
        OAuth2UserInfo oAuth2UserInfo = oAuth2AuthenticationService.getOAuth2UserInfo(OAuth2UserInfoRequest.builder().clientRegistration(clientRegistration).accessToken(accessToken).build());

        OAuth2CallbackResponse callbackResponse;

        //로그인 토큰이 있는 상태에서 인증하는 경우 (계정 연동) 콜백 처리
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String jwt = authorizationHeader.substring(7);
            String username = jwtProvider.extractUsername(jwt);
            oAuth2AuthenticationService.linkAccount(username, provider, oAuth2UserInfo);
            callbackResponse = OAuth2CallbackResponse.builder()
                    .status("success")
                    .build();
        }
        //로그인 인증 콜백처리
        else {
            UserDetails userDetails = oAuth2AuthenticationService.loadUser(clientRegistration.getRegistrationId(), oAuth2UserInfo);
            AccessTokenResponse tokenResponse = authenticationService.issueAccessToken(userDetails);
            callbackResponse = OAuth2CallbackResponse.builder()
                    .status("success")
                    .data(tokenResponse)
                    .build();
        }

        return ResponseEntity.ok(callbackResponse);
    }
}
