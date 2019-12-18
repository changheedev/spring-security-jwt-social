package com.example.springsecurityjwt.oauth2;

import com.example.springsecurityjwt.authentication.AuthorizationCode;
import com.example.springsecurityjwt.authentication.AuthorizationCodeRepository;
import com.example.springsecurityjwt.security.util.CookieUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Optional;
import java.util.UUID;

import static com.example.springsecurityjwt.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@Component
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AuthorizedRedirectUris authorizedRedirectUris;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    public OAuth2AuthenticationSuccessHandler(AuthorizedRedirectUris authorizedRedirectUris, AuthorizationCodeRepository authorizationCodeRepository, HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository) {
        this.authorizedRedirectUris = authorizedRedirectUris;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.httpCookieOAuth2AuthorizationRequestRepository = httpCookieOAuth2AuthorizationRequestRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if(authentication instanceof OAuth2AuthenticationToken) log.debug("true");
        else log.debug("false");
        super.onAuthenticationSuccess(request, response, authentication);
    }

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, UserDetails userDetails) throws IOException {
        String targetUrl = determineTargetUrl(request, response, userDetails.getUsername());

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request, response);
        logger.debug(targetUrl);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    /* 인증을 진행하는 과정에서 쿠키에 저장했던 리디렉션 Uri 에 code 정보를 추가하여 리턴한다.*/
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, String username) {

        String targetUrl = getRedirectUri(request);
        String code = UUID.randomUUID().toString().replace("-", "");
        authorizationCodeRepository.save(AuthorizationCode.builder().code(code).username(username).build());
        authorizationCodeRepository.flush();

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("code", code)
                .build().toUriString();
    }

    private String getRedirectUri(HttpServletRequest request){
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if (!redirectUri.isPresent() || !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new OAuth2AuthenticationFailedException("죄송합니다! 리디렉션 URI 가 존재하지 않거나 승인되지 않은 URI 이므로 인증을 진행할 수 없습니다.");
        }

        return redirectUri.get();
    }

    private void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
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