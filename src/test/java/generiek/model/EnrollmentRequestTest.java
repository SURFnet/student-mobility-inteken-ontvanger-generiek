package generiek.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

class EnrollmentRequestTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void serialization() throws IOException {
        EnrollmentRequest enrollmentRequest = new EnrollmentRequest();
        enrollmentRequest.setId(1L);
        enrollmentRequest.setEduid("eduID");
        enrollmentRequest.setRefreshToken("refreshToken");
        String randomString = RandomStringUtils.randomAscii(500);
        enrollmentRequest.setHomeInstitution("uu+ utrecht" + randomString);
        enrollmentRequest.setPersonAuth(PersonAuthentication.HEADER.name());
        enrollmentRequest.setPersonURI("https://results.uu.university.com" + randomString);
        enrollmentRequest.setScope("https://long.scope.uri.at.somewhere" + randomString);
        enrollmentRequest.setAssociations(new HashSet<>());

        enrollmentRequest = new EnrollmentRequest(enrollmentRequest);

        assertNull(enrollmentRequest.getRefreshToken());
        assertNull(enrollmentRequest.getEduid());

        String base64 = enrollmentRequest.serializeToBase64(objectMapper);
        //Ensure we don't max out on the query param size - which we won't for the GZIP compression
        assertTrue(base64.length() < 1024);

        //Ensure URL decoding / encoding does not change the base64
        String encoded = URLEncoder.encode(base64, Charset.defaultCharset().name());
        assertEquals(base64, encoded);
        String decoded = URLDecoder.decode(encoded, Charset.defaultCharset().name());
        assertEquals(encoded, decoded);

        EnrollmentRequest newEnrollmentRequest = EnrollmentRequest.serializeFromBase64(objectMapper, base64);

        assertEquals(enrollmentRequest.getPersonURI(), newEnrollmentRequest.getPersonURI());
        assertEquals(enrollmentRequest.getScope(), newEnrollmentRequest.getScope());
        assertEquals(enrollmentRequest.getHomeInstitution(), newEnrollmentRequest.getHomeInstitution());
        assertEquals(enrollmentRequest.getPersonAuth(), newEnrollmentRequest.getPersonAuth());
        assertNotNull(newEnrollmentRequest.getIdentifier());
        assertNotNull(newEnrollmentRequest.getCreated());
    }

    @Test
    void serializeFromBase64GZipBomb() {
        String s = Base64.getEncoder().encodeToString(new byte[42 * 1024]);
        assertThrows(IllegalArgumentException.class, () -> EnrollmentRequest.serializeFromBase64(objectMapper, s));
    }


}