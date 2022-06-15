package generiek;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
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
                .get("/internal/health")
                .then()
                .statusCode(SC_OK)
                .body("status", equalTo("UP"));

        given()
                .accept(ContentType.JSON)
                .when()
                .get("/internal/info")
                .then()
                .body("build.artifact", equalTo("student-mobility-inteken-ontvanger-generiek"));
    }
}
