package org.springframework.security.jwtauthenticationfilter.sample.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.jwt.crypto.sign.SignerVerifier;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.Map;

public class DefaultJwtTokenService implements JwtTokenService {

    private ObjectMapper objectMapper = new ObjectMapper();
    private String secret;
    private SignerVerifier signerVerifier;

    public DefaultJwtTokenService(String secret) {
        Assert.notNull(secret, "secret must not be null");
        this.secret = secret;
        this.signerVerifier = new MacSigner(secret);
    }

    @Override
    public String sign(Map<String, Object> claims) {
        try {
            Jwt jwt = JwtHelper.encode(objectMapper.writeValueAsString(claims), signerVerifier);
            return jwt.getEncoded();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            // TODO
            return null;
        }
    }

    @Override
    public Map<String, Object> verify(String token) {
        Jwt jwt = JwtHelper.decodeAndVerify(token, signerVerifier);
        try {
            return objectMapper.readValue(jwt.getClaims(), Map.class);
        } catch (IOException e) {
            e.printStackTrace();
            // TODO
            return null;
        }
    }

    protected ObjectMapper getObjectMapper() {
        return objectMapper;
    }

    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }
}
