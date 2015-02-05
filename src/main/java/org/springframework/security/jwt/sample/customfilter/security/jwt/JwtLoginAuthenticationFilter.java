package org.springframework.security.jwt.sample.customfilter.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtLoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtLoginAuthenticationFilter.class);

    private static final String DEFAULT_FILTER_PROCESS_URL = "/login";
    private static final String DEFAULT_USERNAME_HEADER_NAME = "X-Auth-Username";
    private static final String DEFAULT_PASSWORD_HEADER_NAME = "X-Auth-Password";
    private static final String DEFAULT_AUTHENTICATION_TOKEN_HEADER_NAME = "X-Auth-Token";

    private String usernameHeaderName = DEFAULT_USERNAME_HEADER_NAME;
    private String passwordHeaderName = DEFAULT_PASSWORD_HEADER_NAME;
    private String authenticationTokenHeaderName = DEFAULT_AUTHENTICATION_TOKEN_HEADER_NAME;

    private JwtTokenService jwtTokenService;

    public JwtLoginAuthenticationFilter(AuthenticationManager authenticationManager, JwtTokenService jwtTokenService) {
        super(new AntPathRequestMatcher(DEFAULT_FILTER_PROCESS_URL, "POST"));
        setAuthenticationManager(authenticationManager);
        this.jwtTokenService = jwtTokenService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String username = request.getHeader(usernameHeaderName);
        String password = request.getHeader(passwordHeaderName);
        if (username == null) {
            username = "";
        }
        if (password == null) {
            password = "";
        }
        username = username.trim();
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
        return getAuthenticationManager().authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        response.addHeader(authenticationTokenHeaderName, jwtTokenService.createToken(authResult));
    }

    public String getUsernameHeaderName() {
        return usernameHeaderName;
    }

    public void setUsernameHeaderName(String usernameHeaderName) {
        this.usernameHeaderName = usernameHeaderName;
    }

    public String getPasswordHeaderName() {
        return passwordHeaderName;
    }

    public void setPasswordHeaderName(String passwordHeaderName) {
        this.passwordHeaderName = passwordHeaderName;
    }

    public String getAuthenticationTokenHeaderName() {
        return authenticationTokenHeaderName;
    }

    public void setAuthenticationTokenHeaderName(String authenticationTokenHeaderName) {
        this.authenticationTokenHeaderName = authenticationTokenHeaderName;
    }
}
