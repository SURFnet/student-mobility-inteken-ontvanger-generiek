package generiek.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import generiek.AbstractIntegrationTest;
import generiek.WireMockExtension;
import generiek.model.Association;
import generiek.model.EnrollmentRequest;
import generiek.model.PersonAuthentication;
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
import java.nio.charset.Charset;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.restassured.RestAssured.given;
import static org.apache.http.HttpStatus.SC_MOVED_TEMPORARILY;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;
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
                .post("/associations/external/nope")
                .then()
                .body("status", equalTo(409));
    }

    @Test
    void fullScenario() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());
        doAssociate(correlationId);
    }

    @Test
    void fullScenarioWithPostPersonAuth() throws Exception {
        String state = doAuthorize(PersonAuthentication.FORM.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.FORM.name());
        doAssociate(correlationId);
    }

    @Test
    void associateEnrollmentRequest() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());
        Association association = doAssociate(correlationId);
        doPatchAssociate(association.getAssociationId());
    }

    @Test
    void fullScenarioWithPlay() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());
        doPlayReportBackResults(correlationId);
    }

    @Test
    void invalidServiceRegistryEndpoint() throws JsonProcessingException {
        stubFor(post(urlPathMatching("/api/validate-service-registry-endpoints")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("valid", false)))));

        String location = given().redirects().follow(false)
                .when()
                .header("Content-Type", APPLICATION_FORM_URLENCODED_VALUE)
                .param("personURI", "http://localhost:8081/person")
                .param("personAuth", PersonAuthentication.HEADER.name())
                .param("homeInstitution", "schac.home")
                .param("scope", "write")
                .post("/api/enrollment")
                .header("Location");
        assertEquals("http://localhost:3003?error=Invalid enrollmentRequest", location);
    }

    @Test
    void invalidTokenResult() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());

        String accessToken = accessToken(new HashMap<>());
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
                .header("Location");
        assertEquals("http://localhost:3003?error=eduid is required. Check the ARP for RP:student.mobility.rp.localhost", location);
    }

    @Test
    @SuppressWarnings("unchecked")
    void tokenNotValid() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("associationsURI", "http://localhost:8081/associations")))));
        stubFor(post(urlPathMatching("/oidc/token")).willReturn(aResponse()
                .withStatus(500)));
        //Ensure this goes wrong otherwise no new tokens are fetched
        stubFor(post(urlPathMatching("/associations/external/me")).willReturn(aResponse().withStatus(500)));

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        Map<String, Object> res = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap())
                .pathParam("personId", enrollmentRequest.getEduid())
                .post("/associations/external/{personId}")
                .as(Map.class);

        assertTrue(((String) res.get("description")).startsWith("Error in obtaining new accessToken"));
        assertEquals(true, res.get("error"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void tokenRefresh() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("associationsURI", "http://localhost:8081/associations")))));

        Map<String, String> tokenResult = new HashMap<>();
        tokenResult.put("access_token", "123456");
        tokenResult.put("refresh_token", "123456");

        stubFor(post(urlPathMatching("/oidc/token")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(tokenResult))));
        //Ensure this goes wrong otherwise no new tokens are fetched
        stubFor(post(urlPathMatching("/associations/external/me")).willReturn(aResponse().withStatus(500)));

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        Map<String, Object> res = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap())
                .pathParam("personId", enrollmentRequest.getEduid())
                .post("/associations/external/{personId}")
                .as(Map.class);

        assertEquals(true, res.get("error"));
    }

    @Test
    void associationUriInvalid() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());
        Association association = doAssociate(correlationId);

        stubFor(post(urlPathMatching("/api/associations-uri"))
                .willReturn(aResponse().withStatus(403)
                        .withHeader("Content-Type", "application/json")));

        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap<>())
                .pathParam("associationId", association.getAssociationId())
                .patch("/associations/{associationId}")
                .then()
                .statusCode(403);


    }

    @Test
    @SuppressWarnings("unchecked")
    void associationsUriNotValid() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withStatus(400)));

        Map<String, Object> res = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap<>())
                .pathParam("personId", enrollmentRequest.getEduid())
                .post("/associations/external/{personId}")
                .as(Map.class);

        assertTrue(((String) res.get("description")).startsWith("Error in obtaining associationURI"));
        assertEquals(true, res.get("error"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void ooApiResultsNotValid() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        doStart(correlationId, PersonAuthentication.HEADER.name());

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("resultsURI", "http://localhost:8081/associations")))));


        stubFor(post(urlPathMatching("/associations/external/me")).willReturn(aResponse()
                .withStatus(500)));

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();
        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap<>())
                .pathParam("personId", enrollmentRequest.getEduid())
                .post("/associations/external/{personId}")
                .then()
                .statusCode(500);
    }

    @Test
    void invalidEnrollmentRequest() throws Exception {
        doAuthorize(PersonAuthentication.HEADER.name());

        String accessToken = accessToken(Collections.singletonMap("eduid", "123456789"));
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
                .queryParam("state", "bogus")
                .get("/redirect_uri")
                .header("Location");
        assertEquals("http://localhost:3003?error=Session lost. Please try again", location);
    }

    @Test
    void tokenException() {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        stubFor(post(urlPathMatching("/oidc/token")).willReturn(aResponse()
                .withStatus(400)));

        String location = given().redirects().follow(false)
                .when()
                .queryParam("code", "123456")
                .queryParam("state", state)
                .get("/redirect_uri")
                .then()
                .statusCode(SC_MOVED_TEMPORARILY)
                .extract()
                .header("Location");
        assertEquals("http://localhost:3003?error=Session lost. Please try again", location);
    }

    @Test
    void personEndpointException() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        String offering = readFile("data/offering.json");
        stubFor(get(urlPathMatching("/person")).willReturn(aResponse()
                .withStatus(500)));

        Map result = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("user", "secret")
                .header("X-Correlation-ID", correlationId)
                .body(offering)
                .post("/api/start")
                .as(Map.class);
        assertTrue(((String) result.get("description")).startsWith("Error in retrieving person for enrollmentRequest"));
        assertEquals(true, result.get("error"));
    }

    @Test
    void registrationBrokerException() throws Exception {
        String state = doAuthorize(PersonAuthentication.HEADER.name());
        String correlationId = doToken(state);
        String offering = readFile("data/offering.json");

        stubFor(get(urlPathMatching("/person")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(readFile("data/person.json"))));

        stubFor(post(urlPathMatching("/intake")).willReturn(aResponse()
                .withStatus(500)));

        Map result = given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("user", "secret")
                .header("X-Correlation-ID", correlationId)
                .body(offering)
                .post("/api/start")
                .as(Map.class);
        assertTrue(((String) result.get("description")).startsWith("Error in registration results"));
        assertEquals(true, result.get("error"));
    }

    @SneakyThrows
    private String doAuthorize(String personAuth) {
        stubFor(post(urlPathMatching("/api/validate-service-registry-endpoints")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("valid", true)))));

        String location = given().redirects().follow(false)
                .when()
                .header("Content-Type", APPLICATION_FORM_URLENCODED_VALUE)
                .param("personURI", "http://localhost:8081/person")
                .param("personAuth", personAuth)
                .param("homeInstitution", "schac.home")
                .param("scope", "write")
                .post("/api/enrollment")
                .header("Location");
        assertTrue(location.startsWith(authorizationUri));

        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(location).build().getQueryParams();
        String scope = params.getFirst("scope");
        assertEquals("openid write", URLDecoder.decode(scope, "UTF-8"));
        return URLDecoder.decode(params.getFirst("state"), Charset.defaultCharset().name());
    }


    private String doToken(String state) throws NoSuchProviderException, NoSuchAlgorithmException, JOSEException, IOException {
        Map<String, String> claims = new HashMap<>();
        claims.put("family_name", "Doe");
        claims.put("given_name", "John");
        claims.put("eduid", "1234567890");

        String accessToken = accessToken(claims);
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
        String correlationID = params.getFirst("correlationID");
        assertNotNull(correlationID);
        assertEquals("John", params.getFirst("name"));
        assertEquals("enroll", params.getFirst("step"));
        return correlationID;
    }

    private void doStart(String state, String personAuth) throws IOException {
        String offering = readFile("data/offering.json");
        if (personAuth.equalsIgnoreCase(PersonAuthentication.HEADER.name())) {
            stubFor(get(urlPathMatching("/person")).willReturn(aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(readFile("data/person.json"))));
        } else {
            stubFor(post(urlPathMatching("/person")).willReturn(aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(readFile("data/person.json"))));
        }

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

    private Association doAssociate(String correlationId) throws IOException {
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).get();

        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("associationsURI", "http://localhost:8081/associations")))));

        String content = readFile("data/association_me.json");

        stubFor(post(urlPathMatching("/associations/external/me")).willReturn(aResponse()
                .withBody(content)
                .withHeader("Content-Type", "application/json")
                .withStatus(200)));

        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap<>())
                .pathParam("personId", enrollmentRequest.getEduid())
                .post("/associations/external/{personId}")
                .then()
                .statusCode(200);

        Association association = associationRepository.findByAssociationId("1234567890").get();
        assertEquals(correlationId, association.getEnrollmentRequest().getIdentifier());
        return association;
    }

    private void doPatchAssociate(String associationId) throws IOException {
        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("associationsURI", "http://localhost:8081/associations")))));

        String content = readFile("data/association_me.json");

        stubFor(patch(urlPathMatching("/associations/" + associationId)).willReturn(aResponse()
                .withBody(content)
                .withHeader("Content-Type", "application/json")
                .withStatus(200)));

        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .auth().basic("sis", "secret")
                .body(new HashMap<>())
                .pathParam("associationId", associationId)
                .patch("/associations/{associationId}")
                .then()
                .statusCode(200);
    }

    private void doPlayReportBackResults(String correlationId) throws IOException {
        stubFor(post(urlPathMatching("/api/associations-uri")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("associationsURI", "http://localhost:8081/associations")))));

        stubFor(patch(urlPathMatching("/associations/(.*)")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{}")));

        Map<String, Object> results = objectMapper.readValue(readFile("data/results.json"), Map.class);

        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .header("X-Correlation-ID", correlationId)
                .auth().basic("sis", "secret")
                .body(results)
                .post("/api/play-results")
                .then()
                .statusCode(200);
    }

    private String readFile(String path) throws IOException {
        return IOUtils.toString(new ClassPathResource(path).getInputStream());
    }

    private String accessToken(Map<String, String> claims) throws NoSuchProviderException, NoSuchAlgorithmException, JOSEException, IOException {
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
                .notBeforeTime(new Date(System.currentTimeMillis()));
        claims.forEach(builder::claim);
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