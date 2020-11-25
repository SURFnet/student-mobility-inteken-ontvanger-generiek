package generic.security;

import generic.model.ExtendedOidcUser;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ExtendedOidcUserServiceTest {

    private ExtendedOidcUserService subject = new ExtendedOidcUserService();

    @Test
    void loadUser() {
        ClientRegistration registration = ClientRegistration
                .withRegistrationId("test")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientId("test")
                .tokenUri("http://localhost/token")
                .build();

        Instant now = Instant.now();
        Instant tomorrow = now.plus(1, ChronoUnit.DAYS);
        String tokenValue = UUID.randomUUID().toString();
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                tokenValue,
                now,
                tomorrow);

        OidcIdToken oidcIdToken = new OidcIdToken("123456", now, tomorrow, Collections.singletonMap("sub", "123"));
        OidcUserRequest userRequest = new OidcUserRequest(registration, accessToken, oidcIdToken);
        ExtendedOidcUser oidcUser = (ExtendedOidcUser) subject.loadUser(userRequest);
        assertEquals(tokenValue, oidcUser.getAccessToken().getTokenValue());
    }
}