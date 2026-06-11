package generiek.security;

import lombok.Getter;

import java.io.Serializable;

public class TokenCacheItem implements Serializable {
    private final long expirationTimestamp;

    @Getter
    private final String token;

    public TokenCacheItem(String token, long ttlInSeconds) {
        this.token = token;
        long maxTtlMillis = Math.min(ttlInSeconds, 15 * 60) * 1000;
        this.expirationTimestamp = System.currentTimeMillis() + maxTtlMillis;
    }

    public boolean isExpired() {
        return System.currentTimeMillis() > expirationTimestamp;
    }
}