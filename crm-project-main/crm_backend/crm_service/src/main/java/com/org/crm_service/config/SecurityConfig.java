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
            // 🔥 Enable CORS (IMPORTANT)
            .cors(cors -> {})

            // Disable CSRF
            .csrf(csrf -> csrf.disable())

            // Stateless JWT session
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            .authorizeHttpRequests(auth -> auth

                // Allow root & health
                .requestMatchers("/", "/error", "/favicon.ico").permitAll()

                // Allow auth APIs
                .requestMatchers(
                        "/auth/login",
                        "/auth/register",
                        "/auth/admin"
                ).permitAll()

                // Allow preflight OPTIONS requests
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                // Admin only APIs
                .requestMatchers(
                        "/auth/approve/**",
                        "/auth/reject/**",
                        "/auth/pending"
                ).hasRole("ADMIN")

                // All other APIs require login
                .anyRequest().authenticated()
            )

            // Add JWT Filter
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
