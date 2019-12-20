package com.example.springsecurityjwt;

import com.example.springsecurityjwt.util.JsonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

@AutoConfigureMockMvc
public abstract class SpringMvcTestSupport extends SpringTestSupport {

    @Autowired
    protected MockMvc mockMvc;
}