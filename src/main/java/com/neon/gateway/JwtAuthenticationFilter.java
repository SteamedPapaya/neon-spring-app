package com.neon.gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Spring Cloud Gateway용 JwtAuthenticationFilter는 모든 요청에서 JWT 토큰을 검증하는 역할을 합니다.
 */
@Component
@Slf4j
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private final JwtDecoder jwtDecoder;
    private final ReactiveAuthenticationManager authenticationManager;

    @Value("${jwt.secret}")
    private String secretKey;

    public JwtAuthenticationFilter(JwtDecoder jwtDecoder, ReactiveAuthenticationManager authenticationManager) {
        super(Config.class);
        this.jwtDecoder = jwtDecoder;
        this.authenticationManager = authenticationManager;
    }

    public static class Config {
        // 필터 설정에 필요한 값이 있으면 여기에 추가
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String token = resolveToken(exchange);

            if (token == null || !validateToken(token)) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            // JWT 토큰 디코딩
            return Mono.just(token)
                    .map(tokenString -> jwtDecoder.decode(tokenString))  // jwtDecoder를 통해 디코딩된 Jwt 객체 반환
                    .flatMap(jwt -> {
                        JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(jwt);  // Jwt 객체를 JwtAuthenticationToken에 전달
                        return authenticationManager.authenticate(authenticationToken)  // 인증 처리
                                .doOnNext(authentication -> {
                                    exchange.getRequest().mutate()
                                            .header("X-User-Id", jwt.getSubject())  // 사용자 ID 추가
                                            .build();
                                })
                                .flatMap(authentication -> chain.filter(exchange));
                    })
                    .onErrorResume(e -> {
                        log.error("JWT Decode or Authentication Error: {}", e.getMessage());
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });
        };
    }

    private String resolveToken(ServerWebExchange exchange) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            log.error("JWT Validation Error: {}", e.getMessage());
            return false;
        }
    }
}