package generiek.security;

import java.text.ParseException;
import java.util.Objects;

import com.nimbusds.jwt.JWTParser;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;

@Service
public class TokenCacheService {
    private final CacheManager cacheManager;

    // Constructor injection is de Spring best practice
    public TokenCacheService(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    private Cache getRequiredCache() {
        return Objects.requireNonNull(
                cacheManager.getCache("Tokens"),
                "Cache 'accessTokens' is not configured in the CacheManager!"
        );
    }

    public void saveToken(String key, String accessToken) {
        try {
            var claims = JWTParser.parse(accessToken).getJWTClaimsSet();
            var expSeconds = claims.getExpirationTime().toInstant().getEpochSecond();
            var cacheItem = new TokenCacheItem(accessToken, expSeconds);
            getRequiredCache().put(key, cacheItem);
        } catch (ParseException e) {
            throw new RuntimeException("Failed to parse jwt claims to inspect expiration time", e);
        }
    }

    public String getToken(String key) {
        var cacheItem = getRequiredCache().get(key, TokenCacheItem.class);

        return cacheItem == null || cacheItem.isExpired()
                ? null
                : cacheItem.getToken();
    }
}