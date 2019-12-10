package com.example.springsecurityjwt.security.config;

import com.example.springsecurityjwt.jwt.filter.JwtAuthenticationFilter;
import com.example.springsecurityjwt.security.CustomUserDetailsService;
import com.example.springsecurityjwt.security.oauth.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {

    private final OAuth2ClientProperties oAuth2ClientProperties;
    private final Environment env;
    private final CustomUserDetailsService userDetailsService;
    private final CustomOAuth2UserService oAuth2UserService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    public SecurityConfigurer(OAuth2ClientProperties oAuth2ClientProperties, Environment env, CustomUserDetailsService userDetailsService, CustomOAuth2UserService oAuth2UserService, JwtAuthenticationFilter jwtAuthenticationFilter, OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler, OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler) {
        this.oAuth2ClientProperties = oAuth2ClientProperties;
        this.env = env;
        this.userDetailsService = userDetailsService;
        this.oAuth2UserService = oAuth2UserService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
        this.oAuth2AuthenticationFailureHandler = oAuth2AuthenticationFailureHandler;
    }

    /*
         AuthenticationManager 에서 authenticate 메소드를 실행할때
         내부적으로 사용할 UserDetailsService 와 PasswordEncoder 를 설정
    */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션 사용 x
                .and()
                .csrf().disable()
                .cors()
                .and()
                .formLogin().disable()
                .httpBasic().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/authenticate", "/oauth2/token", "/users").permitAll()
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().authenticated();

        http.oauth2Login()
                .clientRegistrationRepository(clientRegistrationRepository())
                .authorizedClientService(authorizedClientService())
                .authorizationEndpoint()
                .baseUri("/oauth/authorize")
                .authorizationRequestRepository(cookieAuthorizationRequestRepository())
                .and()
                .redirectionEndpoint()
                .baseUri("/oauth/callback/*")
                .and()
                .userInfoEndpoint()
                .userService(oAuth2UserService)
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler);

        //로그인 인증을 진행하는 필터 이전에 jwtAuthenticationFilter 가 실행되도록 설정
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }

    /*PasswordEncoder를 BCryptPasswordEncoder로 사용하도록 Bean 등록*/
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /*
        기본적으로 Spring OAuth2는 HttpSessionOAuth2AuthorizationRequestRepository 를 사용하여 권한 부여 요청을 저장한다.
        그러나 세션 사용 여부를 stateless 로 설정했기 때문에 세션 대신 Base64로 인코딩 된 쿠키에 저장하도록 변경해준다.
    */
    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {

        return new InMemoryOAuth2AuthorizedClientService(
                clientRegistrationRepository());
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {

        List<ClientRegistration> registrations = oAuth2ClientProperties.getRegistration().keySet().stream()
                .map(c -> getRegistration(c))
                .filter(registration -> registration != null)
                .collect(Collectors.toList());

        return new InMemoryClientRegistrationRepository(registrations);
    }

    private ClientRegistration getRegistration(String client) {

        if (client.equals("google")) {
            return CustomOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId(oAuth2ClientProperties.getRegistration().get(client).getClientId())
                    .clientSecret(oAuth2ClientProperties.getRegistration().get(client).getClientSecret())
                    .scope(oAuth2ClientProperties.getRegistration().get(client).getScope())
                    .redirectUriTemplate(oAuth2ClientProperties.getRegistration().get(client).getRedirectUri())
                    .authorizationUri(oAuth2ClientProperties.getProvider().get(client).getAuthorizationUri())
                    .tokenUri(oAuth2ClientProperties.getProvider().get(client).getTokenUri())
                    .userInfoUri(oAuth2ClientProperties.getProvider().get(client).getUserInfoUri())
                    .build();
        }
        if (client.equals("naver")) {
            return CustomOAuth2Provider.NAVER.getBuilder(client)
                    .clientId(oAuth2ClientProperties.getRegistration().get(client).getClientId())
                    .clientSecret(oAuth2ClientProperties.getRegistration().get(client).getClientSecret())
                    .redirectUriTemplate(oAuth2ClientProperties.getRegistration().get(client).getRedirectUri())
                    .scope(oAuth2ClientProperties.getRegistration().get(client).getScope())
                    .authorizationUri(oAuth2ClientProperties.getProvider().get(client).getAuthorizationUri())
                    .tokenUri(oAuth2ClientProperties.getProvider().get(client).getTokenUri())
                    .userInfoUri(oAuth2ClientProperties.getProvider().get(client).getUserInfoUri())
                    .build();
        }
        if (client.equals("kakao")) {
            return CustomOAuth2Provider.KAKAO.getBuilder(client)
                    .clientId(oAuth2ClientProperties.getRegistration().get(client).getClientId())
                    .clientSecret(oAuth2ClientProperties.getRegistration().get(client).getClientSecret())
                    .redirectUriTemplate(oAuth2ClientProperties.getRegistration().get(client).getRedirectUri())
                    .scope(oAuth2ClientProperties.getRegistration().get(client).getScope())
                    .authorizationUri(oAuth2ClientProperties.getProvider().get(client).getAuthorizationUri())
                    .tokenUri(oAuth2ClientProperties.getProvider().get(client).getTokenUri())
                    .userInfoUri(oAuth2ClientProperties.getProvider().get(client).getUserInfoUri())
                    .build();
        }
        return null;
    }
}
