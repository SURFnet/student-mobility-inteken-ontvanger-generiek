package generic.repository;

import generic.model.EnrollmentRequest;

public interface EnrollmentRepository {

    String addEnrollmentRequest(EnrollmentRequest enrollmentRequest);

    EnrollmentRequest findEnrollmentRequest(String identifier);

    void addAccessToken(String identifier, String accessToken);

    void removeEnrollmentRequest(String identifier);
}
