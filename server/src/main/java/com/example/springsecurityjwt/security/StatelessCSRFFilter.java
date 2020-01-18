package com.example.springsecurityjwt.security;

import com.example.springsecurityjwt.util.CookieUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.regex.Pattern;

@Slf4j
public class StatelessCSRFFilter extends OncePerRequestFilter {

    public static final String CSRF_TOKEN = "CSRF-TOKEN";
    public static final String X_CSRF_TOKEN = "X-CSRF-TOKEN";
    private final RequestMatcher requireCsrfProtectionMatcher = new DefaultRequiresCsrfMatcher();
    private final AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        log.debug(request.getHeader("Origin"));

        //csrf 보호가 필요한 method 인지 확인
        if (requireCsrfProtectionMatcher.matches(request)) {
            final String csrfTokenValue = request.getHeader(X_CSRF_TOKEN);
            Optional<Cookie> optCookie = CookieUtils.getCookie(request, CSRF_TOKEN);

            log.debug("csrfTokenValue : {}", csrfTokenValue);
            optCookie.ifPresent(cookie -> log.debug("csrfCookieValue : {}", cookie.getValue()));

            if (!optCookie.isPresent() || !csrfTokenValue.equals(optCookie.get().getValue())) {
                accessDeniedHandler.handle(request, response, new AccessDeniedException(
                        "CSRF 토큰이 유효하지 않습니다."));
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    public static final class DefaultRequiresCsrfMatcher implements RequestMatcher {
        private final Pattern allowedMethods = Pattern.compile("^(GET|HEAD|TRACE|OPTIONS)$");

        @Override
        public boolean matches(HttpServletRequest request) {
            return !allowedMethods.matcher(request.getMethod()).matches();
        }
    }
}
