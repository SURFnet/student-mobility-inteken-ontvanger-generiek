package generic;

import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import generic.mock.MockAuthorizationFilter;
import generic.model.ExtendedOidcUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final Environment environment;
    private final String redirectUri;
    private final String acrValue;
    private final InMemoryClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    public SecurityConfiguration(InMemoryClientRegistrationRepository clientRegistrationRepository,
                                 Environment environment,
                                 @Value("${spring.security.oauth2.client.registration.oidc.redirect-uri}") String redirectUri,
                                 @Value("${oidc.account_linking_context_class_ref}") String acrValue) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.environment = environment;
        this.redirectUri = URI.create(redirectUri).getPath();
        this.acrValue = acrValue;
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .antMatchers("/actuator/**", "/enrollment", "/error");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver =
                new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
        authorizationRequestResolver.setAuthorizationRequestCustomizer(authorizationRequestCustomizer());

        http.csrf().disable()
                .authorizeRequests(authorize -> authorize.anyRequest().authenticated())
                .oauth2Login()
                .userInfoEndpoint()
                .oidcUserService(this.oidcUserService())
                .and()
                .redirectionEndpoint().baseUri(this.redirectUri)
                .and().authorizationEndpoint()
                .authorizationRequestResolver(authorizationRequestResolver);

        if (environment.acceptsProfiles(Profiles.of("test"))) {
            http.addFilterBefore(new MockAuthorizationFilter(), AbstractPreAuthenticatedProcessingFilter.class);
        }
    }

    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcUserService delegate = new OidcUserService();
        return (userRequest) -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);
            OAuth2AccessToken accessToken = userRequest.getAccessToken();
            return new ExtendedOidcUser(accessToken, oidcUser);
        };
    }

    private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
        return customizer -> {
            Map<String, Object> additionalParameters = new HashMap<>();
            List<ClaimsSetRequest.Entry> entries = Stream.of(
                    "eduperson_principal_name",
                    "eduperson_scoped_affiliation",
                    "email",
                    "family_name",
                    "given_name",
                    "eduid",
                    "preferred_username",
                    "schac_home_organization"
            ).map(ClaimsSetRequest.Entry::new).collect(Collectors.toList());
            OIDCClaimsRequest oidcClaimsRequest = new OIDCClaimsRequest().withIDTokenClaimsRequest(new ClaimsSetRequest(entries));
            //This is the enforce account linking by eduID
            additionalParameters.put("acr_values", acrValue);
            //This prevents us from calling the userinfo endpoint
            additionalParameters.put("claims", oidcClaimsRequest.toJSONString());
            //Otherwise we stick to oauth2 instead of oidc
            customizer.scope("openid");
            customizer.state("somethingweird");
            customizer.additionalParameters(additionalParameters);
        };
    }
}
