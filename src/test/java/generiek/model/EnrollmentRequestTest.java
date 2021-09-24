package generiek.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnrollmentRequestTest {

    @Test
    void serialization() throws IOException {
        EnrollmentRequest enrollmentRequest = new EnrollmentRequest();
        enrollmentRequest.setEduid("eduID");
        enrollmentRequest.setRefreshToken("refreshToken");
        String randomString = RandomStringUtils.randomAscii(250);
        enrollmentRequest.setResultsURI("https://results.uu.university.com" + randomString);
        enrollmentRequest.setPersonAuth(PersonAuthentication.HEADER.name());
        enrollmentRequest.setPersonURI("https://results.uu.university.com" + randomString);
        enrollmentRequest.setScope("https://long.scope.uri.at.somewhere" + randomString);

        enrollmentRequest = new EnrollmentRequest(enrollmentRequest);

        assertNull(enrollmentRequest.getRefreshToken());
        assertNull(enrollmentRequest.getEduid());

        ObjectMapper objectMapper = new ObjectMapper();
        String base64 = enrollmentRequest.serializeToBase64(objectMapper);
        //Ensure we don't max out on the query param size - which we won't for the GZIP compression
        assertTrue(base64.length() < Math.round(1024 / 1.5));

        EnrollmentRequest newEnrollmentRequest = EnrollmentRequest.serializeFromBase64(objectMapper, base64);

        assertEquals(enrollmentRequest.getPersonURI(), newEnrollmentRequest.getPersonURI());
        assertEquals(enrollmentRequest.getScope(), newEnrollmentRequest.getScope());
        assertEquals(enrollmentRequest.getResultsURI(), newEnrollmentRequest.getResultsURI());
        assertEquals(enrollmentRequest.getPersonAuth(), newEnrollmentRequest.getPersonAuth());
        assertNotNull(newEnrollmentRequest.getIdentifier());
        assertNotNull(newEnrollmentRequest.getCreated());
    }
}