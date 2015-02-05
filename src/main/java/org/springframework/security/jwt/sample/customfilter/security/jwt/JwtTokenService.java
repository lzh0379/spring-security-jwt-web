package org.springframework.security.jwt.sample.customfilter.security.jwt;

import org.springframework.security.core.Authentication;

public interface JwtTokenService {

    String createToken(Authentication authentication);

    Authentication parseToken();
}
