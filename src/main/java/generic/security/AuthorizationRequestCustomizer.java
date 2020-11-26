package generic.security;

import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import generic.api.EnrollmentEndpoint;
import generic.model.EnrollmentRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AuthorizationRequestCustomizer implements Consumer<OAuth2AuthorizationRequest.Builder> {

    private static final Log LOG = LogFactory.getLog(AuthorizationRequestCustomizer.class);


    private final String acrValue;

    public AuthorizationRequestCustomizer(String acrValue) {
        this.acrValue = acrValue;
    }

    @Override
    public void accept(OAuth2AuthorizationRequest.Builder builder) {
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
        EnrollmentRequest enrollmentRequest = (EnrollmentRequest) RequestContextHolder.currentRequestAttributes()
                .getAttribute(EnrollmentEndpoint.ENROLLMENT_REQUEST_SESSION_KEY, RequestAttributes.SCOPE_SESSION);
        if (enrollmentRequest == null) {
            String message = "No enrollmentRequest is present in the session. No prior FORM POST was done before this authentication or cross-domain cookies are not allowed.";
            LOG.error(message);
            throw new IllegalArgumentException(message);
        }
        //Otherwise we stick to oauth2 instead of oidc
        builder.scope("openid", enrollmentRequest.getScope());
        builder.additionalParameters(additionalParameters);

    }
}
