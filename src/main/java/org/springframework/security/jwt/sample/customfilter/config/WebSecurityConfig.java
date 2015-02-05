package org.springframework.security.jwt.sample.customfilter.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jwt.sample.customfilter.security.jwt.JwtLoginAuthenticationFilter;
import org.springframework.security.jwt.sample.customfilter.security.jwt.JwtProperties;
import org.springframework.security.jwt.sample.customfilter.security.jwt.JwtTokenAuthenticationFilter;
import org.springframework.security.jwt.sample.customfilter.security.jwt.JwtTokenService;
import org.springframework.security.jwt.sample.customfilter.security.jwt.SimpleJwtTokenService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(JwtProperties.class)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtProperties properties;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    public WebSecurityConfig() {
        super(true); // disable defaults
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        JwtTokenService jwtTokenService = new SimpleJwtTokenService();

        JwtLoginAuthenticationFilter jwtLoginAuthenticationFilter = new JwtLoginAuthenticationFilter(authenticationManagerBean(), jwtTokenService);
        if (StringUtils.hasText(properties.getLoginUrl())) {
            jwtLoginAuthenticationFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(properties.getLoginUrl(), "POST"));
        }
        if (StringUtils.hasText(properties.getLoginUsernameHeaderName())) {
            jwtLoginAuthenticationFilter.setUsernameHeaderName(properties.getLoginUsernameHeaderName());
        }
        if (StringUtils.hasText(properties.getLoginPasswordHeaderName())) {
            jwtLoginAuthenticationFilter.setPasswordHeaderName(properties.getLoginPasswordHeaderName());
        }
        if (StringUtils.hasText(properties.getAuthenticationTokenHeaderName())) {
            jwtLoginAuthenticationFilter.setPasswordHeaderName(properties.getAuthenticationTokenHeaderName());
        }


        jwtLoginAuthenticationFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));

        JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter = new JwtTokenAuthenticationFilter();

        // @formatter:off
        http
            .exceptionHandling()
                .and()
            .headers()
                .cacheControl()
                .and()
            .servletApi()
                .and()
            .addFilterBefore(jwtLoginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
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
