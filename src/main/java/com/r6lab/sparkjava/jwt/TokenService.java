package com.r6lab.sparkjava.jwt;

import com.r6lab.sparkjava.jwt.user.Role;
import com.r6lab.sparkjava.jwt.user.User;
import com.r6lab.sparkjava.jwt.user.UserPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public final class TokenService {

    private static final long EXPIRATION_TIME = 10 * 60 * 1000l; // 10 minutes
    private static final String ROLES = "roles";

    private final String jwtSecretKey;

    private final BlacklistedTokenRepository blacklistedTokenRepository = new BlacklistedTokenRepository();

    public TokenService(String jwtSecretKey) {
        this.jwtSecretKey = jwtSecretKey;
    }

    public final void removeExpired() {
        blacklistedTokenRepository.removeExpired();
    }

    public final String newToken(User user) {
        DefaultClaims claims = new DefaultClaims();
        claims.put(ROLES, user.getRoles());
        claims.setSubject(user.getUsername());
        return Jwts.builder()
                .setClaims(claims)
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
    public final UserPrincipal getUserPrincipal(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecretKey)
                .parseClaimsJws(token)
                .getBody();
        List<String> roles = (List<String>) claims.get(ROLES);
        return UserPrincipal.of(claims.getSubject(), roles.stream().map(role -> Role.valueOf(role)).collect(Collectors.toList()));
    }

    public final boolean isTokenBlacklisted(String token) {
        return blacklistedTokenRepository.isTokenBlacklisted(token);
    }

    public final boolean validateToken(String token) {
        if (!isTokenBlacklisted(token)) {
            try {
                getUserPrincipal(token);
                return true;
            } catch (Exception e) {
                return false;
            }
        } else {
            return false;
        }
    }

}
