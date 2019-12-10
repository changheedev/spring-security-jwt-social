package com.example.springsecurityjwt;

import com.example.springsecurityjwt.oauth.OAuthProvider;
import com.example.springsecurityjwt.security.oauth.AuthorizedRedirectUris;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class SpringSecurityJwtApplicationTests {

    private final Logger log = LoggerFactory.getLogger(SpringSecurityJwtApplicationTests.class);

    @Autowired
    private AuthorizedRedirectUris authorizedRedirectUris;

    @Test
    void contextLoads() {
        List<String> listAuthorizaedRedirectUris = authorizedRedirectUris.getAuthorizedRedirectUris();
        assertEquals(listAuthorizaedRedirectUris.size(), 2);
        assertEquals(listAuthorizaedRedirectUris.get(0), "http://localhost:3000/oauth2/result");
        assertEquals(listAuthorizaedRedirectUris.get(1), "http://localhost:3000/oauth2/result");
    }

    @Test
    void enumTest() {
        assertEquals(OAuthProvider.google, OAuthProvider.valueOf("google"));
    }
}
