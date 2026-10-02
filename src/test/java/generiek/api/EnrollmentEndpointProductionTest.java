package generiek.api;

import generiek.AbstractIntegrationTest;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Collections;

import static io.restassured.RestAssured.given;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "features.allow_playground=false"
        })
public class EnrollmentEndpointProductionTest extends AbstractIntegrationTest {

    @Test
    void playResultsNotAllowed() {
        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .header("X-Correlation-ID", "state")
                .auth().basic("sis", "secret")
                .body(Collections.singletonMap("nope", "nope"))
                .post("/api/play-results")
                .then()
                .statusCode(403);
    }

    @Test
    void apiMeNotAllowed() {
        given()
                .when()
                .contentType(ContentType.JSON)
                .accept(ContentType.JSON)
                .header("X-Correlation-ID", "state")
                .auth().basic("sis", "secret")
                .get("/api/me")
                .then()
                .statusCode(403);
    }
}