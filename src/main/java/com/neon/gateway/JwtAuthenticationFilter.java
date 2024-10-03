package com.neon.gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JwtAuthenticationFilter 클래스는 모든 요청에서 JWT 토큰을 검증하는 역할을 합니다.
 * 요청이 들어올 때 JWT를 파싱하고, 유효한 토큰일 경우 요청을 진행시키며,
 * 유효하지 않거나 없는 경우 요청을 차단합니다.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // JWT 비밀키는 application.yml 파일에서 가져오며, jwt.secret 값으로 설정됩니다.
    @Value("${jwt.secret}")
    private String secretKey;

    /**
     * 모든 요청이 이 필터를 거치며, JWT 토큰이 유효한지 검증합니다.
     * @param request  HttpServletRequest: 클라이언트의 요청
     * @param response HttpServletResponse: 클라이언트로 보낼 응답
     * @param filterChain FilterChain: 필터 체인
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Authorization 헤더에서 JWT 토큰을 추출
        String token = resolveToken(request);

        // 토큰이 없거나 유효하지 않으면 401 UNAUTHORIZED 응답
        if (token == null || !validateToken(token)) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return;
        }

        // 유효한 토큰이면 사용자 정보를 설정하고 요청을 계속 처리
        Claims claims = getClaims(token);
        request.setAttribute("userId", claims.getSubject());

        // 요청을 다음 필터로 전달
        filterChain.doFilter(request, response);
    }

    /**
     * Authorization 헤더에서 Bearer 토큰을 추출하는 메서드입니다.
     * @param request HttpServletRequest
     * @return 추출된 JWT 토큰 또는 null
     */
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
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
        try {
            // JWT 파싱 및 서명 검증
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            // 검증 실패 시 false 반환
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