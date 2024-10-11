package com.neon.gateway;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class LoggingFilter extends AbstractGatewayFilterFactory<LoggingFilter.Config> {

    public static class Config {
        // 필터 설정을 위한 빈 클래스
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // 요청 정보 로깅
            String requestPath = exchange.getRequest().getURI().getPath();
            HttpMethod method = exchange.getRequest().getMethod();  // 메서드 가져오기
            log.info("Request: {} {}", method, requestPath);

            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                // 응답 정보 로깅
                HttpStatusCode statusCode = exchange.getResponse().getStatusCode();  // 상태 코드 가져오기
                log.info("Response Status: {}", statusCode != null ? statusCode.value() : "Unknown");
            }));
        };
    }
}