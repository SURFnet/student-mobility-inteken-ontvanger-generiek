package generic;

import generic.mock.MockAuthorizationFilter;
import generic.security.AuthorizationRequestCustomizer;
import generic.security.ExtendedOidcUserService;
import generic.security.OidcCorsConfigurationSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import java.net.URI;

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
                .antMatchers("/api/enrollment", "/actuator/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver =
                new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
        authorizationRequestResolver.setAuthorizationRequestCustomizer(new AuthorizationRequestCustomizer(acrValue));
        http.cors().configurationSource(new OidcCorsConfigurationSource())
                .and()
                .csrf().disable()
                .authorizeRequests(authorize -> authorize.anyRequest().authenticated())
                .oauth2Login()
                .userInfoEndpoint()
                .oidcUserService(new ExtendedOidcUserService())
                .and()
                .redirectionEndpoint().baseUri(this.redirectUri)
                .and().authorizationEndpoint()
                .authorizationRequestResolver(authorizationRequestResolver);

        if (environment.acceptsProfiles(Profiles.of("test"))) {
            http.addFilterBefore(new MockAuthorizationFilter(), AbstractPreAuthenticatedProcessingFilter.class);
        }
    }

}
