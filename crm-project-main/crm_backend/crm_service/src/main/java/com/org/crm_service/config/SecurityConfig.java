package com.org.crm_service.config;

import com.org.crm_service.jwtfilter.JwtFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf -> csrf.disable())

            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            .authorizeHttpRequests(auth -> auth

                // Allow health check & browser access
                .requestMatchers("/", "/error").permitAll()

                // Allow auth APIs
                .requestMatchers(
                        "/auth/login",
                        "/auth/register",
                        "/auth/admin"
                ).permitAll()

                // Allow OPTIONS (Render / Angular preflight)
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                // Admin only
                .requestMatchers(
                        "/auth/approve/**",
                        "/auth/reject/**",
                        "/auth/pending"
                ).hasRole("ADMIN")

                .anyRequest().authenticated()
            )

            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
