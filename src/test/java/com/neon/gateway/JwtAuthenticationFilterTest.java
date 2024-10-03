package com.neon.gateway;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JwtAuthenticationFilterTest {

    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        jwtAuthenticationFilter = new JwtAuthenticationFilter();

        // ReflectionTestUtils를 사용하여 필터에 비밀 키 직접 설정
        ReflectionTestUtils.setField(jwtAuthenticationFilter, "secretKey", "vB2VcZBQRNRTd2KoLvjYx7UPJyYrJLcUOqdv59cob+w=");
    }

    @Test
    public void shouldPassFilterWithValidToken() {
        // 유효한 토큰 생성
        String token = createValidToken("test-user");

        // MockServerHttpRequest를 사용하여 요청 생성
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();

        // MockServerWebExchange 생성
        ServerWebExchange exchange = MockServerWebExchange.from(request);

        // 필터 실행
        JwtAuthenticationFilter.Config config = new JwtAuthenticationFilter.Config(); // 필터 설정 생성
        Mono<Void> result = jwtAuthenticationFilter.apply(config).filter(exchange, chain -> {
            exchange.getResponse().setStatusCode(HttpStatus.OK);
            return Mono.empty();
        });

        // 필터 체인이 정상적으로 요청을 처리했는지 확인
        result.block();
        assertEquals(HttpStatus.OK, exchange.getResponse().getStatusCode());
    }

    @Test
    public void shouldRejectInvalidToken() {
        // 잘못된 토큰을 사용하여 요청 생성
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/user/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer invalid-token")
                .build();

        ServerWebExchange exchange = MockServerWebExchange.from(request);

        // 필터 실행
        JwtAuthenticationFilter.Config config = new JwtAuthenticationFilter.Config(); // 필터 설정 생성
        Mono<Void> result = jwtAuthenticationFilter.apply(config).filter(exchange, chain -> Mono.empty());

        // 필터가 UNAUTHORIZED 상태 코드를 설정해야 함
        result.block();
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    private String createValidToken(String userId) {
        return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1시간 유효
                .signWith(SignatureAlgorithm.HS256, "vB2VcZBQRNRTd2KoLvjYx7UPJyYrJLcUOqdv59cob+w=")  // 테스트용 비밀키
                .compact();
    }
}