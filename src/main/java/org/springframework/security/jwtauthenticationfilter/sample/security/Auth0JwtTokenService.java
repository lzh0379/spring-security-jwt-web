package org.springframework.security.jwtauthenticationfilter.sample.security;

import com.auth0.jwt.JWTSigner;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTVerifyException;
import org.springframework.util.Assert;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

public class Auth0JwtTokenService implements JwtTokenService {

    private String secret;

    private JWTSigner signer;
    private JWTSigner.Options options;
    private JWTVerifier verifier;

    public Auth0JwtTokenService(String secret) {
        this(secret, null);
    }

    public Auth0JwtTokenService(String secret, JWTSigner.Options options) {
        Assert.notNull(secret, "secret must not be null");
        this.secret = secret;
        this.options = options;
        signer = new JWTSigner(secret);
        verifier = new JWTVerifier(secret);
    }

    @Override
    public String sign(Map<String, Object> claims) {
        return signer.sign(claims, options);
    }

    @Override
    public Map<String, Object> verify(String token) {
        try {
            return verifier.verify(token);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (JWTVerifyException e) {
            e.printStackTrace();
        }
        // TODO handle exceptions
        return new HashMap<String, Object>();
    }
}
