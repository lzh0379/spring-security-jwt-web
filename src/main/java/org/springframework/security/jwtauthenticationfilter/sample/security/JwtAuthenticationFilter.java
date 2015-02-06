package org.springframework.security.jwtauthenticationfilter.sample.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JwtAuthenticationFilter extends GenericFilterBean {

    public static final String DEFAULT_USERNAME_HEADER = "X-Auth-Username";
    public static final String DEFAULT_PASSWORD_HEADER = "X-Auth-Password";
    public static final String DEFAULT_TOKEN_HEADER = "X-Auth-Token";

    private AuthenticationManager authenticationManager;
    private JwtTokenService jwtTokenService;

    private RequestMatcher loginRequestMatcher = new AntPathRequestMatcher("/login", "POST");
    private AuthenticationFailureHandler loginFailureHandler = new SimpleUrlAuthenticationFailureHandler();

    private String usernameHeader = DEFAULT_USERNAME_HEADER;
    private String passwordHeader = DEFAULT_PASSWORD_HEADER;
    private String tokenHeader = DEFAULT_TOKEN_HEADER;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtTokenService jwtTokenService) {
        Assert.notNull(authenticationManager, "authenticationManager must not be null");
        Assert.notNull(jwtTokenService, "jwtTokenService must not be null");
        this.authenticationManager = authenticationManager;
        this.jwtTokenService = jwtTokenService;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (loginRequestMatcher.matches(request)) {
            try {
                Authentication authResult = attemptLogin(request, response);
                if (authResult != null) {
                    successfulLogin(request, response, authResult);
                }
            } catch (InternalAuthenticationServiceException failed) {
                logger.error("An internal error occurred while trying to authenticate the user", failed);
                unsuccessfulLogin(request, response, failed);
            } catch (AuthenticationException failed) {
                // Authentication failed
                unsuccessfulLogin(request, response, failed);
            } finally {
                return; // always return after login request
            }
        }

        String token = request.getHeader(tokenHeader);
        if (token != null) {
            Authentication authResult = attemptTokenAuthentication(token);
            if (authResult != null) {
                SecurityContextHolder.getContext().setAuthentication(authResult);
            }
        }

        chain.doFilter(req, res);
    }

    protected Authentication attemptLogin(HttpServletRequest request, HttpServletResponse response) {
        String username = obtainLoginUsername(request);
        String password = obtainLoginPassword(request);
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
        return getAuthenticationManager().authenticate(authRequest);
    }

    protected String obtainLoginUsername(HttpServletRequest request) {
        return request.getHeader(usernameHeader);
    }

    protected String obtainLoginPassword(HttpServletRequest request) {
        return request.getHeader(passwordHeader);
    }

    protected void successfulLogin(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException, ServletException {
        if (logger.isDebugEnabled()) {
            logger.debug("Authentication request success: " + authResult);
        }
        Map<String, Object> claims = provideClaims(request, authResult);
        String token = jwtTokenService.sign(claims);
        response.setHeader(tokenHeader, token);
    }

    protected void unsuccessfulLogin(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        if (logger.isDebugEnabled()) {
            logger.debug("Authentication request failed: " + failed.toString());
        }
        loginFailureHandler.onAuthenticationFailure(request, response, failed);
    }

    protected Map<String, Object> provideClaims(HttpServletRequest request, Authentication authResult) {
        UserDetails userDetails = (UserDetails) authResult.getPrincipal();
        String username = userDetails.getUsername();
        List<String> roles = new ArrayList<String>();
        for (GrantedAuthority authority : userDetails.getAuthorities()) {
            roles.add(authority.getAuthority());
        }
        Map<String, Object> claims = new HashMap<String, Object>();
        claims.put("username", username);
        claims.put("roles", roles);
        return claims;
    }

    protected Authentication attemptTokenAuthentication(String token) throws AuthenticationException, IOException, ServletException {
        // TODO exceptions
        Map<String, Object> claims = jwtTokenService.verify(token);
        String username = obtainUsernameFromClaims(claims);
        List<GrantedAuthority> authorities = obtainAuthoritiesFromClaims(claims);
        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }

    protected String obtainUsernameFromClaims(Map<String, Object> claims) {
        return (String) claims.get("username");
    }

    protected List<GrantedAuthority> obtainAuthoritiesFromClaims(Map<String, Object> claims) {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        for (String role : (List<String>) claims.get("roles")) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        return authorities;
    }

    protected AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    protected JwtTokenService getJwtTokenService() {
        return jwtTokenService;
    }

    protected RequestMatcher getLoginRequestMatcher() {
        return loginRequestMatcher;
    }

    public void setLoginRequestMatcher(RequestMatcher loginRequestMatcher) {
        this.loginRequestMatcher = loginRequestMatcher;
    }

    public void setLoginUrl(String loginUrl) {
        setLoginRequestMatcher(new AntPathRequestMatcher(loginUrl, "POST"));
    }

    protected AuthenticationFailureHandler getLoginFailureHandler() {
        return loginFailureHandler;
    }

    public void setLoginFailureHandler(AuthenticationFailureHandler loginFailureHandler) {
        this.loginFailureHandler = loginFailureHandler;
    }

    protected String getUsernameHeader() {
        return usernameHeader;
    }

    public void setUsernameHeader(String usernameHeader) {
        this.usernameHeader = usernameHeader;
    }

    protected String getPasswordHeader() {
        return passwordHeader;
    }

    public void setPasswordHeader(String passwordHeader) {
        this.passwordHeader = passwordHeader;
    }

    protected String getTokenHeader() {
        return tokenHeader;
    }

    public void setTokenHeader(String tokenHeader) {
        this.tokenHeader = tokenHeader;
    }
}
