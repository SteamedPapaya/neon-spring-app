package com.nemo.chat;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "app")
@Getter
@Setter
public class AppProperties {

    private List<String> allowedOrigins;

    public String[] getAllowedOriginsAsStringArray() {
        return allowedOrigins.toArray(new String[0]);
    }
}