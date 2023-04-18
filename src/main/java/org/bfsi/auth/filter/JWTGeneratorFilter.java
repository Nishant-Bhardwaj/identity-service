package org.bfsi.auth.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bfsi.auth.IdentityServiceApplication;
import org.bfsi.auth.config.SecurityConstants;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

public class JWTGeneratorFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LogManager.getLogger(IdentityServiceApplication.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        LOGGER.info("JWT Generator Filter");

        // Once request is authenticated, it will come here and get Context which is set after validation
        Authentication authentication = SecurityContextHolder
                                            .getContext()
                                            .getAuthentication();

        if (null != authentication) {
            // When Secret key is base 64 encoded
            byte[] keyBytes = Decoders.BASE64.decode(SecurityConstants.JWT_SECRET);
            SecretKey key = Keys.hmacShaKeyFor(keyBytes);

            // When Secret key is not base 64 encoded
            //SecretKey key = Keys.hmacShaKeyFor(SecurityConstants.JWT_SECRET.getBytes(StandardCharsets.UTF_8));

            // Random secret key creation using Spring Security provided methods
            //SecretKey key = SecurityConstants.JWT_SECRET;


            String jwt = Jwts.builder().setIssuer("JAVA POC").setSubject("JWT Token")
                    .claim("username", authentication.getName())
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date()).getTime() + 120000))
                    .signWith(key).compact();

            response.setHeader(SecurityConstants.JWT_HEADER, jwt);

        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !request.getServletPath().equals("/api/v1/auth/token");
    }
}
