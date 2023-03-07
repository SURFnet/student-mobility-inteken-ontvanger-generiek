package generiek.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.SneakyThrows;

import java.net.MalformedURLException;
import java.net.URL;

public class JWTValidator {

    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public JWTValidator(String jwkSetUri, int connectTimeout, int readTimeout, int sizeLimit) throws MalformedURLException {
        this.jwtProcessor = new DefaultJWTProcessor<>();
        DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(connectTimeout, readTimeout, sizeLimit);
        RemoteJWKSet<SecurityContext> remoteJWKSet = new RemoteJWKSet<>(new URL(jwkSetUri), resourceRetriever);
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, remoteJWKSet);
        this.jwtProcessor.setJWSKeySelector(keySelector);
    }

    @SneakyThrows
    public JWTClaimsSet validate(String jwtToken) {
        return jwtProcessor.process(jwtToken, null);
    }

}