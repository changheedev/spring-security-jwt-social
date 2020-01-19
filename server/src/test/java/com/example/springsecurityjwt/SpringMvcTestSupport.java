package com.example.springsecurityjwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

@AutoConfigureMockMvc
public abstract class SpringMvcTestSupport extends SpringTestSupport {

    @Autowired
    protected MockMvc mockMvc;
    protected final String CSRF_TOKEN = UUID.randomUUID().toString();
}