package org.bfsi.auth.filter;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.bfsi.auth.config.SecurityConstants;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class JWTValidatorFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String jwt = parseJWT(request);

        if (null != jwt)
        {
            // When Secret key is base 64 encoded
            byte[] keyBytes = Decoders.BASE64.decode(SecurityConstants.JWT_SECRET);
            SecretKey key = Keys.hmacShaKeyFor(keyBytes);

            // When Secret key is not base 64 encoded
            //SecretKey key = Keys.hmacShaKeyFor(SecurityConstants.JWT_SECRET.getBytes(StandardCharsets.UTF_8));

            // Random secret key creation using Spring Security provided methods
            //SecretKey key = SecurityConstants.JWT_SECRET;

            try{
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(jwt)
                        .getBody();

                String username = String.valueOf(claims.get("username"));

                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(username, null, null);

                // Validated and setting Authentication by passing auth object...
                // so that API will get ath object from 'SecurityContextHolder' and allow access
                SecurityContextHolder.getContext()
                        .setAuthentication(authentication);

            }catch(Exception e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write(e.getMessage());
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String parseJWT(HttpServletRequest request) {
        String header = request.getHeader(SecurityConstants.JWT_HEADER);
        if( null!= header && header.startsWith("Bearer "))
            return header.substring(7);

        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals("/api/v1/auth/token");
    }
}
