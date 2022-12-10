package generiek.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.SneakyThrows;

import java.net.MalformedURLException;
import java.net.URL;

public class JWTValidator {

    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public JWTValidator(String jwkSetUri) throws MalformedURLException {
        this.jwtProcessor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new RemoteJWKSet<>(new URL(jwkSetUri)));
        this.jwtProcessor.setJWSKeySelector(keySelector);
    }

    @SneakyThrows
    public JWTClaimsSet validate(String jwtToken) {
        return jwtProcessor.process(jwtToken, null);
    }

}