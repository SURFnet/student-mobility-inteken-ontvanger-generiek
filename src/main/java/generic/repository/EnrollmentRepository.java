package generic.repository;

import generic.model.EnrollmentRequest;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * This will only work in a single-node environment. When this application is load-balanced then either the
 * load-balancer must evaluate the header X-Correlation-ID for stickiness or something like Redis, Mongo or a RDBMS
 * must be used to store the enrollment data.
 */
@Component
public class EnrollmentRepository {

    private Map<String, EnrollmentRequest> enrollments = new HashMap<>();

    public String addEnrollmentRequest(EnrollmentRequest enrollmentRequest) {
        String identifier = UUID.randomUUID().toString();
        enrollments.put(identifier, enrollmentRequest);
        return identifier;
    }

    public EnrollmentRequest findEnrollmentRequest(String identifier) {
        return enrollments.get(identifier);
    }

    public void addAccessToken(String identifier, String accessToken) {
        EnrollmentRequest enrollmentRequest = findEnrollmentRequest(identifier);
        enrollmentRequest.setAccessToken(accessToken);
    }

    public void removeEnrollmentRequest(String identifier) {
        enrollments.remove(identifier);
    }

}
