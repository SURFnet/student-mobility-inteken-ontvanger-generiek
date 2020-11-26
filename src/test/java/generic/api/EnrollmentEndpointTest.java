package generic.api;

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
import generic.AbstractIntegrationTest;
import generic.WireMockExtension;
import io.restassured.http.ContentType;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLDecoder;
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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static io.restassured.RestAssured.given;
import static org.apache.http.HttpStatus.SC_MOVED_TEMPORARILY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

public class EnrollmentEndpointTest extends AbstractIntegrationTest {

    private static final BouncyCastleProvider bcProvider = new BouncyCastleProvider();

    static {
        Security.addProvider(bcProvider);
    }

    @Autowired
    protected ObjectMapper objectMapper;

    @RegisterExtension
    WireMockExtension mockServer = new WireMockExtension(8081);

    @Value("${oidc.authorization-uri}")
    private String authorizationUri;


    @Test
    void fullScenario() throws Exception {
        MultiValueMap<String, String> authorizeParams = doAuthorize();
        String scope = authorizeParams.getFirst("scope");
        assertEquals("openid write", URLDecoder.decode(scope, "UTF-8"));

        String state = authorizeParams.getFirst("state");

        MultiValueMap<String, String> params = doToken(state);

        assertEquals(state, params.getFirst("identifier"));
        assertEquals("John+Doe", params.getFirst("name"));

        Map result = doStart(state);
        assertEquals("ok", result.get("result"));


    }

    private MultiValueMap<String, String> doAuthorize() {
        String location = given().redirects().follow(false)
                .when()
                .header("Content-Type", APPLICATION_FORM_URLENCODED_VALUE)
                .param("offeringURI", "http://localhost:8081/offering")
                .param("personURI", "http://localhost:8081/person")
                .param("scope", "write")
                .param("returnTo", "http://localhost:8081")
                .post("/api/enrollment")
                .header("Location");
        assertTrue(location.startsWith(authorizationUri));

        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(location).build().getQueryParams();
        return params;
    }


    private MultiValueMap<String, String> doToken(String state) throws NoSuchProviderException, NoSuchAlgorithmException, JOSEException, IOException {
        String accessToken = accessToken();
        Map<String, String> tokenResult = new HashMap<>();
        tokenResult.put("access_token", accessToken);
        tokenResult.put("id_token", accessToken);

        stubFor(post(urlPathMatching("/oidc/token")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(tokenResult))));

        String location = given().redirects().follow(false)
                .when()
                .queryParam("code", "123456")
                .queryParam("state", state)
                .get("/redirect_uri")
                .then()
                .statusCode(SC_MOVED_TEMPORARILY)
                .extract()
                .header("Location");
        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(location).build().getQueryParams();
        return params;
    }

    private Map doStart(String state) throws IOException {
        stubFor(get(urlPathMatching("/offering")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(readFile("data/offering.json"))));

        stubFor(get(urlPathMatching("/person")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(readFile("data/person.json"))));

        stubFor(post(urlPathMatching("/intake")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("result", "ok")))));

        return given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("user", "secret")
                .header("X-Correlation-ID", state)
                .body(Collections.singletonMap("N/", "A"))
                .post("/api/start")
                .as(Map.class);
    }

    private String readFile(String path) throws IOException {
        return IOUtils.toString(new ClassPathResource(path).getInputStream());
    }

    private String accessToken() throws NoSuchProviderException, NoSuchAlgorithmException, JOSEException, IOException {
        String keyId = "key_id";
        RSAKey rsaKey = generateRsaKey(keyId);
        JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK());
        Map<String, Object> jwkSetMap = jwkSet.toJSONObject();
        stubFor(get(urlPathMatching("/oidc/certs")).willReturn(aResponse()
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
                .notBeforeTime(new Date(System.currentTimeMillis()))
                .claim("family_name", "Doe")
                .claim("given_name", "John");
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