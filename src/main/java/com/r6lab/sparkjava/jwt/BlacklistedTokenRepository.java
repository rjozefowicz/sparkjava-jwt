package com.r6lab.sparkjava.jwt;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public final class BlacklistedTokenRepository {

    private final List<BlacklistedTokenHolder> tokens = new CopyOnWriteArrayList<>();

    public void removeExpired() {
        final long currentTimestamp = System.currentTimeMillis();
        tokens.stream().filter(token -> token.getExpirationDate() < currentTimestamp).forEach(token -> {
            System.out.println("Removing token " + token.getToken());
            tokens.remove(token);
        });
    }

    public void addToken(String token, long expirationDate) {
        tokens.add(new BlacklistedTokenHolder(token, expirationDate));
    }

    public boolean isTokenBlacklisted(String token) {
        return tokens.stream().filter(b -> b.getToken().equals(token)).findAny().isPresent();
    }

    private final class BlacklistedTokenHolder {

        private final String token;
        private final long expirationDate;

        public BlacklistedTokenHolder(String token, long expirationDate) {
            this.token = token;
            this.expirationDate = expirationDate;
        }

        public String getToken() {
            return token;
        }

        public long getExpirationDate() {
            return expirationDate;
        }
    }

}
