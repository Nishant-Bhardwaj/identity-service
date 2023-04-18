package org.bfsi.auth.config;

import org.bfsi.auth.filter.JWTGeneratorFilter;
import org.bfsi.auth.filter.JWTValidatorFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.sessionManagement().sessionCreationPolicy((SessionCreationPolicy.STATELESS));

        http.csrf().disable();

        http //READ AS: add 'new JWTValidatorFilter()' Filter Before 'BasicAuthenticationFilter.class(username, password)'
                .addFilterBefore(new JWTValidatorFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new JWTGeneratorFilter(), BasicAuthenticationFilter.class);
            //READ AS: add 'new JWTGeneratorFilter()' Filter After 'BasicAuthenticationFilter.class'

        http
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/welcome", "/api/v1/auth/token", "/api/v1/auth/validate").authenticated()
                .requestMatchers("/api/v1/auth/register").permitAll()
                .and().httpBasic();

        return http.build();
    }
}
