package com.neon.gateway;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class JwtAuthenticationFilterTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private JwtDecoder jwtDecoder;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testValidToken() {
        String validToken = "valid.jwt.token";
        Jwt jwt = Mockito.mock(Jwt.class);

        when(jwtDecoder.decode(anyString())).thenReturn(jwt);

        webTestClient.get().uri("/api/some-endpoint")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    public void testInvalidToken() {
        String invalidToken = "invalid.jwt.token";

        when(jwtDecoder.decode(anyString())).thenThrow(new RuntimeException("Invalid token"));

        webTestClient.get().uri("/api/some-endpoint")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + invalidToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    public void testTokenIsMissing() {
        webTestClient.get().uri("/api/some-endpoint")
                .exchange()
                .expectStatus().isUnauthorized();
    }
}