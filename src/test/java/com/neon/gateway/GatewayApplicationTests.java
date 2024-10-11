package com.neon.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@SpringBootTest
public class GatewayApplicationTests {

    @MockBean
    private JwtDecoder jwtDecoder;  // JwtDecoder 모킹

    @Test
    void contextLoads() {
        // 필요한 테스트를 수행할 수 있는 상태
    }
}