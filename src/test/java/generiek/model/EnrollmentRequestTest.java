package generiek.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class EnrollmentRequestTest {

    @Test
    void serialization() throws IOException {
        EnrollmentRequest enrollmentRequest = new EnrollmentRequest();
        enrollmentRequest.setEduid("eduID");
        enrollmentRequest.setRefreshToken("refreshToken");
        enrollmentRequest.setResultsURI("https://results.uu.university.com");
        enrollmentRequest.setPersonURI("https://results.uu.university.com");
        enrollmentRequest.setScope("https://long.scope.uri.at.somewhere");

        enrollmentRequest = new EnrollmentRequest(enrollmentRequest);

        assertNull(enrollmentRequest.getRefreshToken());
        assertNull(enrollmentRequest.getEduid());

        ObjectMapper objectMapper = new ObjectMapper();
        String base64 = enrollmentRequest.serializeToBase64(objectMapper);
        EnrollmentRequest newEnrollmentRequest = EnrollmentRequest.serializeFromBase64(objectMapper, base64);

        assertEquals(enrollmentRequest.getPersonURI(), newEnrollmentRequest.getPersonURI());
        assertEquals(enrollmentRequest.getScope(), newEnrollmentRequest.getScope());
        assertEquals(enrollmentRequest.getResultsURI(), newEnrollmentRequest.getResultsURI());
        assertNotNull(newEnrollmentRequest.getIdentifier());
        assertNotNull(newEnrollmentRequest.getCreated());
    }
}