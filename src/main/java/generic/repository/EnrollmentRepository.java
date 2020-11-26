package generic.repository;

import generic.model.EnrollmentRequest;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

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
