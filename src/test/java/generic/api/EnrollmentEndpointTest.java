package generic.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import generic.AbstractIntegrationTest;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static io.restassured.RestAssured.given;
import static org.apache.http.HttpStatus.SC_MOVED_TEMPORARILY;
import static org.apache.http.HttpStatus.SC_OK;
import static org.apache.http.HttpStatus.SC_TEMPORARY_REDIRECT;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

public class EnrollmentEndpointTest extends AbstractIntegrationTest {

    @Test
    void offerings()  {
        given()
                .when()
                .header("Content-Type", APPLICATION_FORM_URLENCODED_VALUE)
                .param("offeringId", "http://localhost:8081")
                .post("/enrollment")
                .then()
                .statusCode(SC_MOVED_TEMPORARILY);


    }

}