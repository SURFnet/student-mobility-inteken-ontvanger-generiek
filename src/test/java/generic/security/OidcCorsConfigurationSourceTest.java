package generic.security;

import generic.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;

import java.util.HashMap;

public class OidcCorsConfigurationSourceTest extends AbstractIntegrationTest {

    @Test
    void corsConfiguration() {
        String allowedOrigin = "http://student-mobiliteit.test.surf.nl";

        HashMap<String, Object> expectedHeaders = new HashMap<>();
        expectedHeaders.put("Access-Control-Allow-Origin", allowedOrigin);
        expectedHeaders.put("Access-Control-Allow-Methods", "GET,HEAD,POST");
        expectedHeaders.put("Access-Control-Allow-Credentials", "true");

    }
}