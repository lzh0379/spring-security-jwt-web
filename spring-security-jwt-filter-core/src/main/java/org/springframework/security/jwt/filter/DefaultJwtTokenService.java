/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.jwt.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.SignerVerifier;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.Map;

/**
 * @author Marcel Overdijk
 */
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
