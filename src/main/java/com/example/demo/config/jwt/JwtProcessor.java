package com.example.demo.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.demo.config.auth.UserAccount;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtProcessor {

    public String createJwtToken(UserAccount userAccount){
        return JWT.create()
                .withSubject(userAccount.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", userAccount.getUser().getId())
                .withClaim("username", userAccount.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));
    }

    public String decodeJwtToken(String jwtToken, String secretKey, String claim) {
        return JWT.require(Algorithm.HMAC512(secretKey)).build()
                .verify(jwtToken)
                .getClaim(claim)
                .asString();
    }
    public String extractBearer(String jwtHeader) {
        int pos = jwtHeader.lastIndexOf(" ");
        return jwtHeader.substring(pos + 1);
    }

}
