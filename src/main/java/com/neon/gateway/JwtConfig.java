package com.neon.gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;

@Configuration
public class JwtConfig {

    @Value("${jwt.secret}")
    private String secretKey;

    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder() {
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
        return NimbusReactiveJwtDecoder.withSecretKey(key).build();
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager(ReactiveJwtDecoder reactiveJwtDecoder) {
        return new JwtReactiveAuthenticationManager(reactiveJwtDecoder);
    }
}