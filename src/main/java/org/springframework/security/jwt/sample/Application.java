package org.springframework.security.jwt.sample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.web.savedrequest.NullRequestCache;

@SpringBootApplication
@EnableResourceServer
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    public ApplicationSecurity applicationSecurity() {
        return new ApplicationSecurity();
    }

    @Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
    protected static class ApplicationSecurity extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                .anonymous()
                    .disable()
                .csrf()
                    .disable()
                .authorizeRequests()
                    .antMatchers("/api/**").hasRole("USER")
                    .antMatchers("/management/**").hasRole("ADMIN")
                    .and()
                .requestCache()
                    .requestCache(new NullRequestCache())
                    .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
            // @formatter:on
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            // @formatter:off
            auth
                .inMemoryAuthentication()
                    .withUser("admin").password("pwd").roles("ADMIN").and()
                    .withUser("user").password("pwd").roles("USER");
            // @formatter:on
        }
    }

    @Configuration
    @EnableAuthorizationServer
    protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {

        @Autowired
        private AuthenticationManager authenticationManager;

        @Bean
        public JwtAccessTokenConverter accessTokenConverter() {
            return new JwtAccessTokenConverter();
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
            // @formatter:off
            oauthServer
                .tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
                .checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
            // @formatter:on
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints.authenticationManager(authenticationManager).accessTokenConverter(accessTokenConverter());
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            // @formatter:off
		 	clients.inMemory()
		        .withClient("my-trusted-client")
		            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
		            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
		            .scopes("read", "write", "trust")
		            .accessTokenValiditySeconds(60)
 		    .and()
		        .withClient("my-client-with-registered-redirect")
		            .authorizedGrantTypes("authorization_code")
		            .authorities("ROLE_CLIENT")
		            .scopes("read", "trust")
		            .redirectUris("http://anywhere?key=value")
 		    .and()
		        .withClient("my-client-with-secret")
		            .authorizedGrantTypes("client_credentials", "password")
		            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
		            .scopes("read", "write")
		            .secret("secret");
		    // @formatter:on
        }
    }
}
