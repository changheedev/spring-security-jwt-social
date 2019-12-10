package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.jwt.JwtProvider;
import com.example.springsecurityjwt.security.AuthorityType;
import com.example.springsecurityjwt.security.CustomUserDetails;
import com.example.springsecurityjwt.users.SignUpRequest;
import com.example.springsecurityjwt.users.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class AuthenticationApiTest {

    private final Logger log = LoggerFactory.getLogger(AuthenticationApiTest.class);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private AuthorizationCodeRepository authorizationCodeRepository;
    @Autowired
    private JwtProvider jwtProvider;

    private final URI AUTHENTICATION_REDIRECT_URI = URI.create("http://localhost:3000/oauth/result");

    @BeforeEach
    public void setup() {
        userRepository.deleteAll();
    }

    @Test
    @Transactional
    public void 인증_후_Authorization_Code_리디렉션_테스트() throws Exception {

        //given
        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");

        //when
        String strRedirectedUri = requestAuthentication(signUpRequest.getEmail(), signUpRequest.getPassword(), AUTHENTICATION_REDIRECT_URI.toString());

        //then
        URI uriRedirectedUri = URI.create(strRedirectedUri);
        String query = uriRedirectedUri.getQuery();
        String code = query.substring(query.indexOf("=") + 1);

        assertEquals(uriRedirectedUri.getHost(), AUTHENTICATION_REDIRECT_URI.getHost());
        assertEquals(uriRedirectedUri.getPort(), AUTHENTICATION_REDIRECT_URI.getPort());
        assertEquals(uriRedirectedUri.getPath(), AUTHENTICATION_REDIRECT_URI.getPath());
        log.debug(code);
        assertTrue(code.matches("[0-9a-fA-F]{8}[0-9a-fA-F]{4}[0-9a-fA-F]{4}[0-9a-fA-F]{4}[0-9a-fA-F]{12}"));
    }

    @Test
    @Transactional
    public void Access_Token_발급_테스트() throws Exception {
        //given
        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");
        String code = UUID.randomUUID().toString().replace("-", "");

        AuthorizationCode authorizationCode = AuthorizationCode.builder().username(signUpRequest.getEmail()).code(code).build();
        authorizationCodeRepository.save(authorizationCode);

        //when
        AccessTokenResponse accessTokenResponse = getAccessToken(signUpRequest.getEmail(), code, null, AuthorizationGrantType.AUTHORIZATION_CODE);

        //then
        assertNotNull(accessTokenResponse.getToken());
        assertNotNull(accessTokenResponse.getRefreshToken());
    }

    @Test
    @Transactional
    public void Token_Refresh_테스트() throws Exception {
        //given
        SignUpRequest signUpRequest = registerTestUser("test@email.com", "ChangHee", "password");
        CustomUserDetails userDetails = CustomUserDetails.builder().email(signUpRequest.getEmail()).name(signUpRequest.getName()).authorities(Arrays.asList(AuthorityType.ROLE_MEMBER)).build();
        String refreshToken = jwtProvider.generateRefreshToken(userDetails);

        //when
        AccessTokenResponse accessTokenResponse = getAccessToken(signUpRequest.getEmail(), null, refreshToken, AuthorizationGrantType.REFRESH_TOKEN);

        //then
        assertNotNull(accessTokenResponse.getToken());
        assertNotNull(accessTokenResponse.getRefreshToken());
        assertNotEquals(refreshToken, accessTokenResponse.getRefreshToken());
    }

    private SignUpRequest registerTestUser(String email, String name, String password) throws Exception {
        SignUpRequest signUpRequest = SignUpRequest.builder()
                .email(email)
                .name(name)
                .password(password)
                .build();

        requestSignUpApi(signUpRequest);

        return signUpRequest;
    }

    private AccessTokenResponse getAccessToken(String username, String code, String refreshToken, AuthorizationGrantType grantType) throws Exception {
        AuthorizationRequest authorizationRequest = null;
        if (grantType.equals(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            authorizationRequest = AuthorizationRequest.builder().username(username).code(code).grantType(grantType).build();
        } else if (grantType.equals(AuthorizationGrantType.REFRESH_TOKEN)) {
            authorizationRequest = AuthorizationRequest.builder().username(username).refreshToken(refreshToken).grantType(grantType).build();
        }
        AccessTokenResponse accessTokenResponse = requestAuthorization(authorizationRequest);
        return accessTokenResponse;
    }

    private void requestSignUpApi(SignUpRequest signUpRequest) throws Exception {
        MvcResult mvcResult = mockMvc.perform(post("/users")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn();
    }

    private String requestAuthentication(String username, String password, String redirectUrl) throws Exception {

        AuthenticationRequest authenticationRequest = AuthenticationRequest.builder()
                .username(username)
                .password(password)
                .redirectUri(redirectUrl)
                .build();

        MvcResult mvcResult = mockMvc.perform(post("/authenticate")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsString(authenticationRequest)))
                .andExpect(status().isFound()) //302 Redirect
                .andExpect(redirectedUrlPattern(redirectUrl + "?code={[0-9a-fA-F]{8}[0-9a-fA-F]{4}[0-9a-fA-F]{4}[0-9a-fA-F]{4}[0-9a-fA-F]{12}}"))
                .andDo(print()).andReturn();

        return mvcResult.getResponse().getRedirectedUrl();
    }

    private AccessTokenResponse requestAuthorization(AuthorizationRequest authorizationRequest) throws Exception {

        MvcResult mvcResult = mockMvc.perform(post("/oauth2/token")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsString(authorizationRequest)))
                .andExpect(status().isOk())
                .andDo(print()).andReturn();

        String result = mvcResult.getResponse().getContentAsString();
        AccessTokenResponse accessTokenResponse = objectMapper.readValue(result, AccessTokenResponse.class);

        return accessTokenResponse;
    }
}
