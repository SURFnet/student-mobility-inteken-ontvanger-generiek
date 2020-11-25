package generic.security;

import generic.model.ExtendedOidcUser;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public class ExtendedOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    final OidcUserService delegate = new OidcUserService();

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = delegate.loadUser(userRequest);
        OAuth2AccessToken accessToken = userRequest.getAccessToken();
        return new ExtendedOidcUser(accessToken, oidcUser);
    }
}
