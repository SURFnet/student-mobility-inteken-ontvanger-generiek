package generic.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import generic.WireMockExtension;
import io.restassured.RestAssured;
import io.restassured.common.mapper.TypeRef;
import io.restassured.filter.session.SessionFilter;
import io.restassured.http.ContentType;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;

import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static io.restassured.RestAssured.given;
import static org.apache.http.HttpStatus.SC_MOVED_TEMPORARILY;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"backend.url=http://localhost:8081/intake"})
@ActiveProfiles("test")
public class EnrollmentEndpointTest {

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

    @Test
    void callback() {
        given().redirects().follow(false)
                .when()
                .get("/callback")
                .then()
                .statusCode(SC_MOVED_TEMPORARILY)
                .header("Location", "http://localhost:3003/enroll");
    }

    @Test
    void me() throws IOException {
        SessionFilter sessionFilter = new SessionFilter();
        given().filter(sessionFilter)
                .when()
                .header("Content-Type", APPLICATION_FORM_URLENCODED_VALUE)
                .param("offering", "http://localhost:8081/offering")
                .param("person", "http://localhost:8081/person")
                .param("scope", "groups")
                .param("returnTo", "http://localhost:8081")
                .post("/enrollment")
                .then()
                .statusCode(SC_MOVED_TEMPORARILY)
                .header("Location", "http://localhost:" + port + "/callback");

        stubFor(get(urlPathMatching("/offering")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(readFile("data/offering.json"))));
        stubFor(get(urlPathMatching("/person")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(readFile("data/person.json"))));

        Map<String, Map<String, Object>> result = given().filter(sessionFilter)
                .when()
                .get("/me")
                .as(new TypeRef<Map<String, Map<String, Object>>>() {
                });
        assertEquals("Maartje", result.get("person").get("givenName"));
        assertEquals("Test-INFOMQNM-20FS", result.get("offering").get("abbreviation"));
    }

    @Test
    void start() throws JsonProcessingException {
        stubFor(post(urlPathMatching("/intake")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(objectMapper.writeValueAsString(Collections.singletonMap("result", "ok")))));

        given()
                .when()
                .contentType(ContentType.JSON)
                .body(Collections.singletonMap("N/", "A"))
                .post("/start")
                .then()
                .body("result", equalTo("ok"));
    }

    private String readFile(String path) throws IOException {
        return IOUtils.toString(new ClassPathResource(path).getInputStream());
    }


}