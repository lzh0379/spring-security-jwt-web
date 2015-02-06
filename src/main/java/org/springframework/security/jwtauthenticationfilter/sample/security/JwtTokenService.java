package org.springframework.security.jwtauthenticationfilter.sample.security;

import java.util.Map;

public interface JwtTokenService {

    String sign(Map<String, Object> claims);

    Map<String, Object> verify(String token);
}
