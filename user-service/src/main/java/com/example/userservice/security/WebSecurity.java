package com.example.userservice.security;

import com.example.userservice.service.UserService;
import java.util.Arrays;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Slf4j
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurity {

    private final Environment env;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager,
                                                   UserService userService) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((authorize) -> authorize
//                        .requestMatchers("/users/**").permitAll()
                        .requestMatchers("/actuator/**").permitAll()
                        .requestMatchers("/healthcheck/**").permitAll()
                        .requestMatchers("/error/**").permitAll()
                        .requestMatchers("/login/**").permitAll()
                        .requestMatchers("/**").access(((authentication, request) -> {
                                    String clientIp = request.getRequest().getRemoteAddr();
                                    log.debug("client Ip is = {}", clientIp);

                                    String[] allowedIps = {"192.168.0.12", "127.0.0.1"};
                                    boolean isAllowed = Arrays.asList(allowedIps).contains(clientIp);

                                    return new AuthorizationDecision(isAllowed);
                                })
                        )
                ).formLogin(AbstractHttpConfigurer::disable)
                .authenticationManager(authenticationManager)
                .sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                .addFilter(customAuthenticationFilter(authenticationManager, userService));

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http,
                                                       UserService userService,
                                                       BCryptPasswordEncoder passwordEncoder) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(
                AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userService).passwordEncoder(passwordEncoder);

        return authenticationManagerBuilder.build();
    }

    @Bean
    public CustomAuthenticationFilter customAuthenticationFilter(AuthenticationManager authenticationManager,
                                                                 UserService userService) {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManager,
                userService, env);
        customAuthenticationFilter.setFilterProcessesUrl("/login");
        return customAuthenticationFilter;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
