package generiek;

import generiek.repository.EnrollmentRepository;
import io.restassured.RestAssured;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "backend.url=http://localhost:8081/intake",
                "oidc.authorization-uri=http://localhost:8081/oidc/authorize",
                "oidc.token-uri=http://localhost:8081/oidc/token",
                "oidc.jwk-set-uri=http://localhost:8081/oidc/certs"
        })
public abstract class AbstractIntegrationTest {

    @LocalServerPort
    protected int port;

    @Autowired
    protected EnrollmentRepository enrollmentRepository;

    @BeforeEach
    public void before() {
        RestAssured.port = port;
        enrollmentRepository.deleteAll();
    }

}
