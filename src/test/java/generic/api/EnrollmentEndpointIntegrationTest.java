package generic.api;

import generic.AbstractIntegrationTest;
import io.restassured.filter.session.SessionFilter;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.endsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

@ActiveProfiles(value = "prod", inheritProfiles = false)
public class EnrollmentEndpointIntegrationTest extends AbstractIntegrationTest {

    @Test
    void authentication() throws UnsupportedEncodingException {
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

    @Test
    void authenticationBeforeFormPost() {
        given()
                .redirects().follow(false)
                .when()
                .get("/oauth2/authorization/oidc")
                .then()
                .header("Location", endsWith("/oauth2/authorization/oidc"));
    }

}