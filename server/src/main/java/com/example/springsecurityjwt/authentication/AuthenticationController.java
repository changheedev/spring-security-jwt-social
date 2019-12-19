package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.authentication.oauth2.*;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.jwt.JwtProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
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
public class AuthenticationController{

    private final String OAUTH2_AUTHORIZATION_COOKIE_NAME = "oauth2_params";

    private final AuthenticationService authenticationService;
    private final OAuth2AuthenticationService oAuth2AuthenticationService;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final JwtProvider jwtProvider;

    public AuthenticationController(AuthenticationService authenticationService, OAuth2AuthenticationService oAuth2AuthenticationService, ClientRegistrationRepository clientRegistrationRepository, JwtProvider jwtProvider) {
        this.authenticationService = authenticationService;
        this.oAuth2AuthenticationService = oAuth2AuthenticationService;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.jwtProvider = jwtProvider;
    }

    @PostMapping("/authenticate")
    public void authenticateUsernamePassword(@RequestBody AuthenticationRequest authenticationRequest, HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            if(!isAuthorizedRedirectUri(authenticationRequest.getRedirectUri()))
                throw new AuthenticationFailedException("허가되지 않은 리디렉션 URI 입니다.");
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
            onAuthenticationSuccess(request, response, AuthenticationResponse.builder().username(authenticationRequest.getUsername()).redirectUri(authenticationRequest.getRedirectUri()).build());
        } catch (UsernameNotFoundException e) {
            throw new UsernameNotFoundException("이메일 또는 비밀번호가 틀렸습니다.");
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("이메일 또는 비밀번호가 틀렸습니다.");
        }
    }

    /* 사용자에게 토큰을 발급해주는 요청을 처리하는 컨트롤러 */
    @PostMapping("/oauth2/token")
    public ResponseEntity<?> issueAuthenticationToken(@RequestBody AuthorizationRequest authorizationRequest) throws Exception {

        AccessTokenResponse accessTokenResponse = null;

        if (authorizationRequest.getGrantType().equals(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            accessTokenResponse = authenticationService.exchangeAuthorizationCodeToAccessToken(authorizationRequest.getCode(), authorizationRequest.getUsername());
        } else if (authorizationRequest.getGrantType().equals(AuthorizationGrantType.REFRESH_TOKEN)) {
            accessTokenResponse = authenticationService.refreshAuthenticationToken(authorizationRequest.getRefreshToken(), authorizationRequest.getUsername());
        }

        return ResponseEntity.ok(accessTokenResponse);
    }

    /* 사용자의 소셜 로그인 요청을 받아 각 소셜 서비스로 인증을 요청하는 컨트롤러 */
    @GetMapping("/oauth2/authorize/{provider}")
    public void redirectSocialAuthorizationPage(@PathVariable String provider, OAuth2AuthorizationRequestParams requestParams, HttpServletRequest request, HttpServletResponse response) throws Exception {

        if(!isAuthorizedRedirectUri(requestParams.getRedirectUri()))
            throw new AuthenticationFailedException("허가되지 않은 리디렉션 URI 입니다.");

        CookieUtils.addCookie(response, OAUTH2_AUTHORIZATION_COOKIE_NAME, URLEncoder.encode(JsonUtils.toJson(requestParams),"utf-8"), 180);

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);

        String authorizationUri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getAuthorizationUri())
                .queryParam("client_id", clientRegistration.getClientId())
                .queryParam("response_type", "code")
                .queryParam("include_granted_scopes", true)
                .queryParam("scope", String.join("+", clientRegistration.getScopes()))
                .queryParam("state", UUID.randomUUID().toString().replace("-", ""))
                .queryParam("redirect_uri", expandRedirectUri(request, clientRegistration))
                .build().encode(StandardCharsets.UTF_8).toUriString();

        response.sendRedirect(authorizationUri);
    }

    /* 각 소셜 서비스로부터 인증 결과를 처리하는 컨트롤러 */
    @RequestMapping("/oauth2/callback/{provider}")
    public ResponseEntity<?> oAuth2AuthenticationCallback(@PathVariable String provider, OAuth2CallbackRequest callbackRequest, HttpServletRequest request) {

        final String authorizationHeader = request.getHeader("Authorization");
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);

        String accessToken = oAuth2AuthenticationService.getOAuth2AccessToken(OAuth2AccessTokenRequest.builder().clientRegistration(clientRegistration).code(code).state(state).build());
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
