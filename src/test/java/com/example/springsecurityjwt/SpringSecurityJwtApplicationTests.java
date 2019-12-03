package com.example.springsecurityjwt;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SpringSecurityJwtApplicationTests {

	Logger log = LoggerFactory.getLogger(SpringSecurityJwtApplicationTests.class);

	@Test
	void contextLoads() {
		log.debug("Hello");
	}

}
