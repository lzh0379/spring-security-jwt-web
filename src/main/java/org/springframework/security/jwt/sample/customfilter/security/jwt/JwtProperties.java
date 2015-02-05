package org.springframework.security.jwt.sample.customfilter.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.validation.constraints.NotNull;

@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    @NotNull
    private String secret;

    private Integer expirySeconds;
    private String loginUrl;
    private String loginUsernameHeaderName;
    private String loginPasswordHeaderName;
    private String authenticationTokenHeaderName;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public Integer getExpirySeconds() {
        return expirySeconds;
    }

    public void setExpirySeconds(Integer expirySeconds) {
        this.expirySeconds = expirySeconds;
    }

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public String getLoginUsernameHeaderName() {
        return loginUsernameHeaderName;
    }

    public void setLoginUsernameHeaderName(String loginUsernameHeaderName) {
        this.loginUsernameHeaderName = loginUsernameHeaderName;
    }

    public String getLoginPasswordHeaderName() {
        return loginPasswordHeaderName;
    }

    public void setLoginPasswordHeaderName(String loginPasswordHeaderName) {
        this.loginPasswordHeaderName = loginPasswordHeaderName;
    }

    public String getAuthenticationTokenHeaderName() {
        return authenticationTokenHeaderName;
    }

    public void setAuthenticationTokenHeaderName(String authenticationTokenHeaderName) {
        this.authenticationTokenHeaderName = authenticationTokenHeaderName;
    }
}
