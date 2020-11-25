package generic.mock;

import generic.model.ExtendedOidcUser;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class MockAuthorizationFilter implements Filter {

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain) throws IOException, ServletException {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "john.doe@ou.org");
        claims.put("email", "john.doe@ou.org");
        claims.put("eduperson_scoped_affiliation", Arrays.asList("student@ou.org"));

        List<GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("USER"));
        DefaultOidcUser oidcUser = new DefaultOidcUser(
                authorities,
                new OidcIdToken("value", Instant.now(), Instant.now().plus(90, ChronoUnit.DAYS), claims));
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                UUID.randomUUID().toString(),
                Instant.now(),
                Instant.now().plus(1, ChronoUnit.DAYS));
        ExtendedOidcUser extendedOidcUser = new ExtendedOidcUser(accessToken, oidcUser);
        TestingAuthenticationToken auth = new TestingAuthenticationToken(extendedOidcUser, "N/A", authorities);
        SecurityContextHolder.getContext().setAuthentication(auth);

        filterChain.doFilter(req, res);
    }
}
