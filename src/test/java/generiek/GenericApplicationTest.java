package generiek;

import io.restassured.RestAssured;
import io.restassured.common.mapper.TypeRef;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.apache.http.HttpStatus.SC_OK;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;

class GenericApplicationTest {

    @Test
    void main() {
        GenericApplication.main(new String[]{"--server.port=8082"});
        RestAssured.port = 8082;
        given()
                .when()
                .get("/internal/health")
                .then()
                .statusCode(SC_OK)
                .body("status", equalTo("UP"));

        Map<String, Object> info = given()
                .accept(ContentType.JSON)
                .when()
                .get("/internal/info")
                .as(new TypeRef<Map<String, Object>>() {
                });
        assertFalse(info.isEmpty());
    }
}
