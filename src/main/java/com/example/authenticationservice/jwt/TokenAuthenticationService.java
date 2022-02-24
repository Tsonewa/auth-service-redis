package com.example.authenticationservice.jwt;

import com.example.authenticationservice.domain.AuthenticationTokenImpl;
import com.example.authenticationservice.domain.SessionUser;
import com.example.authenticationservice.service.RedisService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.Sha512DigestUtils;

public class TokenAuthenticationService {

    private final RedisService service;

    private long EXPIRATIONTIME = 1000 * 60 * 60; // 1 hr

    @Value("${jwt.token.secret}")
    private final String secret;

    private static final String TOKEN_PREFIX = "Bearer ";

    private static final String HEADER_TOKEN = "Authorization";


    public TokenAuthenticationService(RedisService service, String key) {
        this.service = service;
        secret = Sha512DigestUtils.shaHex(key);
    }

    public void addAuthentication(HttpServletResponse response, AuthenticationTokenImpl auth) {
        // We generate a token now.
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", auth.getPrincipal());
        claims.put("hash", auth.getHash());
        String JWT = Jwts.builder()
                .setSubject(auth.getPrincipal().toString())
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
        response.addHeader(HEADER_TOKEN, TOKEN_PREFIX + " " + JWT);
    }

    public Authentication getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(HEADER_TOKEN);
        if (token == null) {
            return null;
        }
        //remove "Bearer" text
        token = token.replace(TOKEN_PREFIX, "").trim();

        //Validating the token
        if (token != null && !token.isEmpty()) {
            // parsing the token.`
            Claims claims = null;
            try {
                claims = Jwts.parser()
                        .setSigningKey(secret)
                        .parseClaimsJws(token).getBody();

            } catch ( Exception e) {
                return null;
            }

            //Valid token and now checking to see if the token is actally expired or alive by quering in redis.
            if (claims != null && claims.containsKey("username")) {
                String username = claims.get("username").toString();
                String hash = claims.get("hash").toString();
                SessionUser user = (SessionUser) service.getValue(String.format("%s:%s", username,hash), SessionUser.class);
                if (user != null) {
                    AuthenticationTokenImpl auth = new AuthenticationTokenImpl(user.getUsername(), Collections.emptyList());
                    auth.setDetails(user);
                    auth.authenticate();
                    return auth;
                } else {
                    return new UsernamePasswordAuthenticationToken(null, null);
                }

            }
        }
        return null;
    }
}
