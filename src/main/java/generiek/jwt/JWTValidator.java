package generiek.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import generiek.api.EnrollmentEndpoint;
import lombok.SneakyThrows;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.HashSet;
import java.util.Set;

public class JWTValidator {

    private static final Log LOG = LogFactory.getLog(EnrollmentEndpoint.class);

    private final String jwkSetUri;
    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public JWTValidator(String jwkSetUri, int connectTimeout, int readTimeout, int sizeLimit) throws MalformedURLException {
        this.jwkSetUri = jwkSetUri;
        this.jwtProcessor = new DefaultJWTProcessor<>();
        DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(connectTimeout, readTimeout, sizeLimit);
        RemoteJWKSet<SecurityContext> remoteJWKSet = new RemoteJWKSet<>(new URL(jwkSetUri), resourceRetriever);
        Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
        jwsAlgs.add(JWSAlgorithm.RS256);
        jwsAlgs.add(JWSAlgorithm.ES256);
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(jwsAlgs, remoteJWKSet);
        this.jwtProcessor.setJWSKeySelector(keySelector);
    }

    public JWTClaimsSet validate(String jwtToken) throws ParseException, BadJOSEException, JOSEException {
        try {
            return jwtProcessor.process(jwtToken, null);
        } catch (ParseException | BadJOSEException | JOSEException e) {
            LOG.error(String.format("Error in validation of JWT token for token %s against jwkSetUri %s",
                    jwtToken, this.jwkSetUri), e);
            throw e;
        }
    }

}