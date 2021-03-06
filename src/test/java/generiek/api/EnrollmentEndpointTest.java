package generiek.api;

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
import generiek.AbstractIntegrationTest;
import generiek.WireMockExtension;
import generiek.model.EnrollmentRequest;
import io.restassured.http.ContentType;
import lombok.SneakyThrows;
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
import static org.hamcrest.Matchers.equalTo;
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

    @Value("${broker.url}")
    private String brokerUrl;

    @Test
    void expiredEnrollmentRequest() {
        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("user", "secret")
                .header("X-Correlation-ID", "nope")
                .body(Collections.singletonMap("N/", "A"))
                .post("/api/start")
                .then()
                .body("status", equalTo(409));
    }

    @Test
    void expiredEnrollmentRequestInResults() {
        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(Collections.singletonMap("N/", "A"))
                .post("/api/results")
                .then()
                .body("status", equalTo(409));
    }

    @Test
    void fullScenario() throws Exception {
        String state = doAuthorize();
        doToken(state);
        doStart(state);
        doReportBackResults(state);
    }

    @Test
    void fullScenarioWithPlay() throws Exception {
        String state = doAuthorize();
        doToken(state);
        doStart(state);
        doPlayReportBackResults(state);
    }

    @SneakyThrows
    private String doAuthorize() {
        stubFor(post(urlPathMatching("/api/validate-service-registry-endpoints")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("valid", true)))));


        String location = given().redirects().follow(false)
                .when()
                .header("Content-Type", APPLICATION_FORM_URLENCODED_VALUE)
                .param("personURI", "http://localhost:8081/person")
                .param("resultsURI", "http://localhost:8081/results")
                .param("scope", "write")
                .post("/api/enrollment")
                .header("Location");
        assertTrue(location.startsWith(authorizationUri));

        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(location).build().getQueryParams();
        String scope = params.getFirst("scope");
        assertEquals("openid write", URLDecoder.decode(scope, "UTF-8"));
        return params.getFirst("state");
    }


    private void doToken(String state) throws NoSuchProviderException, NoSuchAlgorithmException, JOSEException, IOException {
        String accessToken = accessToken();
        Map<String, String> tokenResult = new HashMap<>();
        tokenResult.put("access_token", accessToken);
        tokenResult.put("refresh_token", accessToken);
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

        assertTrue(location.startsWith(brokerUrl));
        assertEquals(state, params.getFirst("correlationID"));
        assertEquals("John", params.getFirst("name"));
        assertEquals("enroll", params.getFirst("step"));
    }

    private void doStart(String state) throws IOException {
        String offering = readFile("data/offering.json");

        stubFor(get(urlPathMatching("/person")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(readFile("data/person.json"))));

        stubFor(post(urlPathMatching("/intake")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("result", "ok")))));

        Map result = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("user", "secret")
                .header("X-Correlation-ID", state)
                .body(offering)
                .post("/api/start")
                .as(Map.class);
        assertEquals("ok", result.get("result"));
    }

    private void doReportBackResults(String state) throws IOException {
        Map<String, String> tokenResult = Collections.singletonMap("access_token", UUID.randomUUID().toString());

        stubFor(post(urlPathMatching("/oidc/token")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(tokenResult))));

        stubFor(post(urlPathMatching("/results")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withStatus(200)));

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(state).get();
        Map<String, Object> results = objectMapper.readValue(readFile("data/results.json"), Map.class);
        results.put("personId", enrollmentRequest.getEduid());

        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(results)
                .post("/api/results")
                .then()
                .statusCode(200);
    }

    private void doPlayReportBackResults(String state) throws IOException, NoSuchAlgorithmException, JOSEException, NoSuchProviderException {
        Map<String, String> tokenResult = Collections.singletonMap("access_token", UUID.randomUUID().toString());

        stubFor(post(urlPathMatching("/oidc/token")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(tokenResult))));

        stubFor(post(urlPathMatching("/results")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withStatus(200)));

        Map<String, Object> results = objectMapper.readValue(readFile("data/results.json"), Map.class);

        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .header("X-Correlation-ID", state)
                .auth().basic("sis", "secret")
                .body(results)
                .post("/api/play-results")
                .then()
                .statusCode(200);
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
                .claim("given_name", "John")
                .claim("eduid", "1234567890 ");
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