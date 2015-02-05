package org.springframework.security.jwt.sample.customfilter.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

public class JwtTokenAuthenticationFilter extends GenericFilterBean {

    private static final String DEFAULT_TOKEN_HEADER_NAME = "X-Auth-Token";

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenAuthenticationFilter.class);

    private String tokenHeaderName = DEFAULT_TOKEN_HEADER_NAME;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        logger.debug("in jwt token authentication filter");

        chain.doFilter(request, response);
    }
}
