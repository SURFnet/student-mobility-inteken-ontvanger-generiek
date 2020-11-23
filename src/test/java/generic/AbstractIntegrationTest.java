package generic;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.RestAssured;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static io.restassured.RestAssured.given;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class AbstractIntegrationTest {

    @LocalServerPort
    protected int port;

    @Autowired
    protected ObjectMapper objectMapper;

    @BeforeEach
    public void before() {
        RestAssured.port = port;
    }

    @RegisterExtension
    WireMockExtension mockServer = new WireMockExtension(8081);

    protected String accessToken() throws NoSuchProviderException, NoSuchAlgorithmException, JOSEException, IOException {
        String keyId = "key_id";
        RSAKey rsaKey = generateRsaKey(keyId);
        JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK());
        Map<String, Object> jwkSetMap = jwkSet.toJSONObject();
        stubFor(get(urlPathMatching("/certs")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(jwkSetMap))));

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .audience("audiences")
                .expirationTime(Date.from(Instant.now().plus(60 * 60, ChronoUnit.SECONDS)))
                .jwtID(UUID.randomUUID().toString())
                .issuer("issuer")
                .claim("scope", Arrays.asList("openid", "profile"))
                .issueTime(Date.from(Instant.now()))
                .subject("subject")
                .notBeforeTime(new Date(System.currentTimeMillis()));
        JWTClaimsSet claimsSet = builder.build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT)
                .keyID(keyId).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        JWSSigner jwsSigner = new RSASSASigner(rsaKey);
        signedJWT.sign(jwsSigner);
        return signedJWT.serialize();
    }

    private RSAKey generateRsaKey(String keyID) throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(keyID)
                .build();
    }

}