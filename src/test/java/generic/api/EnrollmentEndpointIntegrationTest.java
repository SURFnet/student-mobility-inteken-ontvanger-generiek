package generic.api;

import io.restassured.RestAssured;
import io.restassured.filter.session.SessionFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class EnrollmentEndpointIntegrationTest {

    @LocalServerPort
    protected int port;

    @BeforeEach
    public void before() {
        RestAssured.port = port;
    }

    @Test
    void oicd() throws UnsupportedEncodingException {
        SessionFilter sessionFilter = new SessionFilter();
        given().filter(sessionFilter)
                .when()
                .header("Content-Type", APPLICATION_FORM_URLENCODED_VALUE)
                .param("offering", "http://localhost:8081/offering")
                .param("person", "http://localhost:8081/person")
                .param("scope", "write")
                .param("returnTo", "http://localhost:8081")
                .post("/api/enrollment");

        String location = given()
                .redirects().follow(false)
                .filter(sessionFilter)
                .when()
                .get("/oauth2/authorization/oidc")
                .header("Location");
        MultiValueMap<String, String> params = UriComponentsBuilder.fromHttpUrl(location).build().getQueryParams();
        String scope = params.getFirst("scope");
        assertEquals("openid write", URLDecoder.decode(scope, "UTF-8"));
    }

}