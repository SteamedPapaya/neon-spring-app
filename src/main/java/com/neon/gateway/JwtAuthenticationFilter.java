package com.neon.gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * WebFlux 기반의 JwtAuthenticationFilter 클래스는 모든 요청에서 JWT 토큰을 검증하는 역할을 합니다.
 * 비동기 방식으로 요청을 처리하며, 유효한 토큰이 있을 때만 요청을 계속 처리합니다.
 */
@Component
@Slf4j
public class JwtAuthenticationFilter implements WebFilter {

    @Value("${jwt.secret}")
    private String secretKey;

    /**
     * WebFlux 기반의 필터 메서드로, 비동기 방식으로 JWT 토큰을 검증합니다.
     * @param exchange ServerWebExchange: 요청과 응답 정보를 포함한 객체
     * @param chain WebFilterChain: 필터 체인
     * @return Mono<Void>: 비동기 응답
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = resolveToken(exchange);

        log.info("JWT token: {}", token);
        log.info("validateToken: {}", validateToken(token));
        // 토큰이 없거나 유효하지 않으면 401 응답
        if (token == null || !validateToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // 유효한 토큰이면 사용자 정보를 설정하고 체인 통과
        Claims claims = getClaims(token);
        exchange.getRequest().mutate().header("X-User-Id", claims.getSubject()).build();

        log.info("JWT Token: {}", claims);
        return chain.filter(exchange);
    }

    /**
     * Authorization 헤더에서 JWT 토큰을 추출하는 메서드입니다.
     * @param exchange ServerWebExchange
     * @return 추출된 JWT 토큰 또는 null
     */
    private String resolveToken(ServerWebExchange exchange) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * JWT 토큰이 유효한지 검증하는 메서드입니다.
     * @param token 검증할 JWT 토큰
     * @return 토큰이 유효한 경우 true, 그렇지 않으면 false
     */
    private boolean validateToken(String token) {
        log.info("JWT={}", token);
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            log.error("JWT={}", e.getMessage());
            return false;
        }
    }

    /**
     * JWT 토큰에서 사용자 정보를 추출하는 메서드입니다.
     * @param token JWT 토큰
     * @return JWT의 Claims 객체
     */
    private Claims getClaims(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }
}