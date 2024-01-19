package generiek.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.RandomStringUtils;
import org.jetbrains.annotations.TestOnly;
import org.junit.jupiter.api.Test;

import java.io.IOException;
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
        enrollmentRequest.setHomeInstitution("uu.utrecht" + randomString);
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

    @Test
    void serializeStateTest() throws IOException {
        String s = "H4sIAAAAAAAAAH2MsQ5AQBAFf0W2xlaa6yQkan%2BgOHFxbi%2F7DoX4d1doKSeZmYsiGVpSijDMKiGdFXada4FTh8q7sNbBs8gUHR8NR6uQAN4slTTldujbrh8zIMP34O2Kb0Mtdp%2BQT8vfie4HirfhR7QAAAA%3D";
        EnrollmentRequest enrollmentRequest = EnrollmentRequest.serializeFromBase64(objectMapper, s);
        assertEquals("rontw-surf.osiris-link.nl", enrollmentRequest.getHomeInstitution());
    }
}