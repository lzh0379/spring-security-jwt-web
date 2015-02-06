package org.springframework.security.jwtauthenticationfilter.sample.config;

import com.auth0.jwt.JWTSigner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jwtauthenticationfilter.sample.security.Auth0JwtTokenService;
import org.springframework.security.jwtauthenticationfilter.sample.security.JwtAuthenticationFilter;
import org.springframework.security.jwtauthenticationfilter.sample.security.JwtProperties;
import org.springframework.security.jwtauthenticationfilter.sample.security.JwtTokenService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtProperties properties;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    public SecurityConfig() {
        super(true); // disable defaults
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        JWTSigner.Options options = new JWTSigner.Options()
                .setExpirySeconds(properties.getTokenExpirySeconds())
                .setIssuedAt(true);
        JwtTokenService jwtTokenService = new Auth0JwtTokenService(properties.getTokenSecret(), options);

        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManagerBean(), jwtTokenService);
        if (StringUtils.hasText(properties.getLoginUrl())) {
            jwtAuthenticationFilter.setLoginUrl(properties.getLoginUrl());
        }

        // @formatter:off
        http
            .exceptionHandling()
                .and()
            .headers()
                .cacheControl()
                .and()
            .servletApi()
                .and()
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeRequests()
                .antMatchers("/api/**").hasAuthority("USER")
                .antMatchers("/management/**").hasAuthority("ADMIN");
        // @formatter:on
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // @formatter:off
        auth
            .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
        // @formatter:on
    }
}
