package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.authentication.oauth2.*;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountDTO;
import com.example.springsecurityjwt.authentication.oauth2.service.OAuth2Service;
import com.example.springsecurityjwt.authentication.oauth2.service.OAuth2ServiceFactory;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.users.UserType;
import com.example.springsecurityjwt.util.CookieUtils;
import com.example.springsecurityjwt.util.JsonUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Arrays;

@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final InMemoryOAuth2RequestRepository inMemoryOAuth2RequestRepository;
    private final RestTemplate restTemplate;
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

        String state = generateState();

        // 콜백에서 사용할 요청 정보를 저장
        inMemoryOAuth2RequestRepository.saveOAuth2Request(state, OAuth2AuthorizationRequest.builder().referer(request.getHeader("referer")).redirectUri(redirectUri).callback(callback).build());

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);
        OAuth2Service oAuth2Service = OAuth2ServiceFactory.getOAuth2Service(restTemplate, provider);
        oAuth2Service.redirectAuthorizePage(clientRegistration, state, response);
    }

    /* 각 소셜 서비스로부터 인증 결과를 처리하는 컨트롤러 */
    @RequestMapping("/oauth2/callback/{provider}")
    public void oAuth2AuthenticationCallback(@PathVariable String provider, OAuth2AuthorizationResponse oAuth2AuthorizationResponse, HttpServletRequest request, HttpServletResponse response, @AuthenticationPrincipal CustomUserDetails loginUser) throws Exception {

        //인증을 요청할 때 저장했던 request 정보를 가져온다.
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = inMemoryOAuth2RequestRepository.deleteOAuth2Request(oAuth2AuthorizationResponse.getState());

        //유저가 로그인 페이지에서 로그인을 취소하거나 오류가 발생했을때 처리
        if (oAuth2AuthorizationResponse.getError() != null) {
            redirectWithErrorMessage(oAuth2AuthorizationRequest.getReferer(), oAuth2AuthorizationResponse.getError(), response);
            return;
        }

        //사용자의 요청에 맞는 OAuth2 클라이언트 정보를 매핑한다
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);
        OAuth2Service oAuth2Service = OAuth2ServiceFactory.getOAuth2Service(restTemplate, provider);

        //토큰과 유저 정보를 요청
        OAuth2Token oAuth2Token = oAuth2Service.getAccessToken(clientRegistration, oAuth2AuthorizationResponse.getCode(), oAuth2AuthorizationResponse.getState());
        OAuth2UserInfo oAuth2UserInfo = oAuth2Service.getUserInfo(clientRegistration, oAuth2Token.getToken());

        //로그인에 대한 콜백 처리
        if (oAuth2AuthorizationRequest.getCallback().equalsIgnoreCase("login")) {
            UserDetails userDetails = authenticationService.registerOrLoadOAuth2User(provider, oAuth2Token, oAuth2UserInfo);
            createTokenCookie(userDetails, response);
        }
        //계정 연동에 대한 콜백 처리
        else if (oAuth2AuthorizationRequest.getCallback().equalsIgnoreCase("link")) {
            //로그인 상태가 아니면
            if (loginUser == null) {
                redirectWithErrorMessage(oAuth2AuthorizationRequest.getReferer(), "unauthorized", response);
                return;
            }

            try {
                authenticationService.linkOAuth2Account(loginUser.getUsername(), provider, oAuth2Token, oAuth2UserInfo);
            } catch (OAuth2ProcessException e) {
                redirectWithErrorMessage(oAuth2AuthorizationRequest.getReferer(), "already_linked", response);
                return;
            }
        }

        //콜백 성공
        response.sendRedirect(oAuth2AuthorizationRequest.getRedirectUri());
    }

    @PostMapping("/oauth2/unlink/{provider}")
    public void unlinkOAuth2Account(@PathVariable String provider, @AuthenticationPrincipal CustomUserDetails loginUser) {

        //로그인 상태가 아니면
        if (loginUser == null)
            throw new OAuth2ProcessException("Unauthorized");

        //소셜 계정으로 생성된 계정이면 연동 해제 방지
        if (loginUser.getType().equals(UserType.OAUTH))
            throw new OAuth2ProcessException("This account created by social");

        //사용자의 요청에 맞는 OAuth2 클라이언트 정보를 매핑한다
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);
        OAuth2Service oAuth2Service = OAuth2ServiceFactory.getOAuth2Service(restTemplate, provider);

        OAuth2AccountDTO oAuth2AccountDTO = authenticationService.loadOAuth2Account(provider, loginUser.getId());

        //토큰이 만료된 경우 재발급 요청 후 연동 해제 요청
        if (LocalDateTime.now().isAfter(oAuth2AccountDTO.getTokenExpiredAt())) {
            OAuth2Token oAuth2Token = oAuth2Service.refreshOAuth2Token(clientRegistration, oAuth2AccountDTO.getRefreshToken());
            oAuth2Service.unlink(clientRegistration, oAuth2Token.getToken());
        } else oAuth2Service.unlink(clientRegistration, oAuth2AccountDTO.getToken());

        //연동해제된 소셜 계정 정보 삭제
        authenticationService.unlinkOAuth2Account(oAuth2AccountDTO.getProvider(), oAuth2AccountDTO.getProviderId(), loginUser.getId());
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

    private void redirectWithErrorMessage(String uri, String message, HttpServletResponse response) throws IOException {
        String redirectUri = UriComponentsBuilder.fromUriString(uri)
                .replaceQueryParam("error", message).encode().build().toUriString();
        response.sendRedirect(redirectUri);
    }

    private String generateState() {
        SecureRandom random = new SecureRandom();
        return new BigInteger(130, random).toString(32);
    }
}
