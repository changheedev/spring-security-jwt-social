package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.oauth2.*;
import com.example.springsecurityjwt.oauth2.AuthorizedRedirectUris;
import com.example.springsecurityjwt.security.util.CookieUtils;
import com.example.springsecurityjwt.util.JsonUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@Slf4j
public class AuthenticationController{

    private final String OAUTH2_AUTHORIZATION_COOKIE_NAME = "oauth2_params";

    private final AuthenticationService authenticationService;
    private final OAuth2AuthenticationService oAuth2AuthenticationService;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final AuthenticationManager authenticationManager;
    private final AuthorizedRedirectUris authorizedRedirectUris;

    public AuthenticationController(AuthenticationService authenticationService, OAuth2AuthenticationService oAuth2AuthenticationService, ClientRegistrationRepository clientRegistrationRepository, AuthenticationManager authenticationManager, AuthorizedRedirectUris authorizedRedirectUris) {
        this.authenticationService = authenticationService;
        this.oAuth2AuthenticationService = oAuth2AuthenticationService;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authenticationManager = authenticationManager;
        this.authorizedRedirectUris = authorizedRedirectUris;
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
    public void oAuth2AuthenticationCallBack(@PathVariable String provider, @RequestParam String state, @RequestParam String code, HttpServletRequest request, HttpServletResponse response) throws Exception {

        OAuth2AuthorizationRequestParams requestParams = getOAuth2AuthorizationRequestParamsFromCookie(request, response);

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);

        String accessToken = oAuth2AuthenticationService.getOAuth2AccessToken(OAuth2AccessTokenRequest.builder().clientRegistration(clientRegistration).code(code).state(state).build());
        OAuth2UserInfo oAuth2UserInfo = oAuth2AuthenticationService.getOAuth2UserInfo(OAuth2UserInfoRequest.builder().clientRegistration(clientRegistration).accessToken(accessToken).build());

        if (requestParams.getRequestType().equals("login")) {
            //연동된 계정 정보가 없고 이메일이 없으면
            if (!oAuth2AuthenticationService.findOAuth2Account(clientRegistration.getRegistrationId(), oAuth2UserInfo.getId()) && oAuth2UserInfo.getEmail() == null) {
                //이메일 입력화면으로 이동


            } else { // Authorization Code 발급
                UserDetails userDetails = oAuth2AuthenticationService.loadUser(clientRegistration.getRegistrationId(), oAuth2UserInfo);
                onAuthenticationSuccess(request, response, AuthenticationResponse.builder().username(userDetails.getUsername()).redirectUri(requestParams.getRedirectUri()).build());
            }
        } else if (requestParams.getRequestType().equals("link")) {
            //계정 연동 처리
        }
    }

    /* 소셜 유저 정보에서 추가적으로 필요한 정보들을 입력받아 인증을 처리하는 컨트롤러 */
    @PostMapping("/oauth2/attributes")
    public void registerOAuth2AccountWithAdditionalAttributes(@RequestBody OAuth2AdditionalAttributesRequest oAuth2AdditionalAttributesRequest, HttpServletRequest request, HttpServletResponse response) throws Exception {
        OAuth2AuthorizationRequestParams requestParams = getOAuth2AuthorizationRequestParamsFromCookie(request, response);

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("id", oAuth2AdditionalAttributesRequest.getId());
        attributes.put("name", oAuth2AdditionalAttributesRequest.getName());
        attributes.put("email", oAuth2AdditionalAttributesRequest.getEmail());

        DefaultOAuth2UserInfo defaultOAuth2UserInfo = new DefaultOAuth2UserInfo(attributes);
        UserDetails userDetails = oAuth2AuthenticationService.loadUser(oAuth2AdditionalAttributesRequest.getRegistrationId(), defaultOAuth2UserInfo);

        onAuthenticationSuccess(request, response, AuthenticationResponse.builder().username(userDetails.getUsername()).redirectUri(requestParams.getRedirectUri()).build());
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

    /* 소셜 인증 요청시 쿠키에 임시로 저장한 클라이언트의 데이터를 읽어온다. */
    private OAuth2AuthorizationRequestParams getOAuth2AuthorizationRequestParamsFromCookie(HttpServletRequest request, HttpServletResponse response) throws Exception{

        String jsonParams = CookieUtils.getCookie(request, OAUTH2_AUTHORIZATION_COOKIE_NAME).map(Cookie::getValue)
                .orElseThrow(() -> new AuthenticationFailedException("parameter \"" + OAUTH2_AUTHORIZATION_COOKIE_NAME + "\" is null"));

        return JsonUtils.fromJson(URLDecoder.decode(jsonParams, "utf-8"), OAuth2AuthorizationRequestParams.class);
    }

    /* 인증 성공시 클라이언트가 요청한 RedirectUri 로 토큰발급을 위한 Authorization Code 를 포함하여 리디렉션을 시켜준다. */
    private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, AuthenticationResponse authenticationResponse ) throws Exception{
        String code = authenticationService.generateAuthorizationCode(authenticationResponse.getUsername());
        String targetUrl = UriComponentsBuilder.fromUriString(authenticationResponse.getRedirectUri())
                .queryParam("code", code).build().toString();
        CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_COOKIE_NAME);
        response.sendRedirect(targetUrl);
    }

    /* 인증 실패시 클라이언트가 요청한 RedirectUri 로 토큰발급을 위한 Authorization Code 를 포함하여 리디렉션을 시켜준다. */
    private void onAuthenticationFailed(HttpServletRequest request, HttpServletResponse response, AuthenticationResponse authenticationResponse) throws Exception{
        String code = authenticationService.generateAuthorizationCode(authenticationResponse.getUsername());
        String targetUrl = UriComponentsBuilder.fromUriString(authenticationResponse.getRedirectUri())
                .queryParam("code", code).build().toString();
        CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_COOKIE_NAME);
        response.sendRedirect(targetUrl);
    }

    /* 요청에 포함된 redirectUri 가 허용된 uri 인지 체크 */
    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);

        return authorizedRedirectUris.getAuthorizedRedirectUris()
                .stream()
                .anyMatch(authorizedRedirectUri -> {
                    // Only validate host and port. Let the clients use different paths if they want to
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    if (authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }
}
