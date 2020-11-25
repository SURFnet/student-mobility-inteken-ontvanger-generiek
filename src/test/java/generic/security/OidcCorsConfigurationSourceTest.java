package generic.security;

import static org.junit.jupiter.api.Assertions.*;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.restassured.RestAssured;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.HashMap;

import static io.restassured.RestAssured.given;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public class OidcCorsConfigurationSourceTest {

    @LocalServerPort
    protected int port;

    @BeforeEach
    public void before() {
        RestAssured.port = port;
    }

    @Test
    void corsConfiguration() {
        String allowedOrigin = "http://student-mobiliteit.test.surf.nl";

        HashMap<String, Object> expectedHeaders = new HashMap<>();
        expectedHeaders.put("Access-Control-Allow-Origin", allowedOrigin);
        expectedHeaders.put("Access-Control-Allow-Methods", "GET,HEAD,POST");
        expectedHeaders.put("Access-Control-Allow-Credentials", "true");

        given().redirects().follow(false)
                .when()
                .header(HttpHeaders.ORIGIN, allowedOrigin)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET", "POST")
                .options("/api/me")
                .then()
                .statusCode(200)
                .headers(expectedHeaders);


    }
}