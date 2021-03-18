package generiek;

import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.apache.http.HttpStatus.SC_OK;
import static org.hamcrest.Matchers.equalTo;

class GenericApplicationTest {

    @Test
    void main() {
        GenericApplication.main(new String[]{"--server.port=8088"});
        RestAssured.port = 8088;
        given()
                .when()
                .get("/actuator/health")
                .then()
                .statusCode(SC_OK)
                .body("status", equalTo("UP"));
    }
}
