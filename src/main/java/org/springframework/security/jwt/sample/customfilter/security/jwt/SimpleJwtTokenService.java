package org.springframework.security.jwt.sample.customfilter.security.jwt;

import com.auth0.jwt.JWTSigner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.HashMap;
import java.util.Map;

public class SimpleJwtTokenService implements JwtTokenService {

    private String secret;

    public SimpleJwtTokenService(String secret) {
        this.secret = secret;
    }

    @Override
    public String createToken(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal(); // does this always work?
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", userDetails.getUsername());
        claims.put("roles", userDetails.getAuthorities());
        // TODO set expiry via Options
        return new JWTSigner(secret).sign(claims);
    }

    @Override
    public Authentication parseToken() {
        // TODO
        return null;
    }
}
