package generic.api;

import generic.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.apache.http.HttpStatus.SC_MOVED_TEMPORARILY;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

public class EnrollmentEndpointTest extends AbstractIntegrationTest {

    @Test
    void offerings() {
        given()
                .when()
                .header("Content-Type", APPLICATION_FORM_URLENCODED_VALUE)
                .param("offering", "http://localhost:8081/offering")
                .param("person", "http://localhost:8081/person")
                .param("scope", "openid")
                .param("returnTo", "http://localhost:8081")
                .post("/enrollment")
                .then()
                .statusCode(SC_MOVED_TEMPORARILY)
                .header("Location", "http://localhost:" + port + "/me");


    }

}