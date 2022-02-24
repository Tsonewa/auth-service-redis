package com.example.authenticationservice;

import com.example.authenticationservice.service.RedisService;
import com.example.authenticationservice.jwt.TokenAuthenticationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class AuthenticationServiceApplication {

    @Autowired
    private RedisService redisService;

    @Value("${ENC_KEY}")
    private String encKey;

    @Bean
    public TokenAuthenticationService tokenAuthService() {
        return new TokenAuthenticationService(redisService,encKey);
    }

    @Bean
    public ObjectMapper mapper(){
        return new ObjectMapper();
    }
    public static void main(String[] args) {
        SpringApplication.run(AuthenticationServiceApplication.class, args);
    }

}
