package com.r6lab.sparkjava.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

public final class TokenService {

    private static final long EXPIRATION_TIME = 10 * 60 * 1000l; // 10 minutes

    private final String jwtSecretKey;

    private final BlacklistedTokenRepository blacklistedTokenRepository = new BlacklistedTokenRepository();

    public TokenService(String jwtSecretKey) {
        this.jwtSecretKey = jwtSecretKey;
    }

    public final void removeExpired() {
        blacklistedTokenRepository.removeExpired();
        ;
    }

    public final String newToken(String userName) {
        return Jwts.builder()
                .setSubject(userName)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, jwtSecretKey)
                .compact();
    }

    public final void revokeToken(String token) {
        Date expirationDate = Jwts.parser()
                .setSigningKey(jwtSecretKey)
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        blacklistedTokenRepository.addToken(token, expirationDate.getTime());
    }

    /**
     * throws ExpiredJwtException if token has expired
     *
     * @param token
     * @return
     */
    public final String getUserName(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecretKey)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public final boolean isTokenBlacklisted(String token) {
        return blacklistedTokenRepository.isTokenBlacklisted(token);
    }

    public final boolean validateToken(String token) {
        if (!isTokenBlacklisted(token)) {
            try {
                getUserName(token);
                return true;
            } catch (Exception e) {
                return false;
            }
        } else {
            return false;
        }
    }

}
