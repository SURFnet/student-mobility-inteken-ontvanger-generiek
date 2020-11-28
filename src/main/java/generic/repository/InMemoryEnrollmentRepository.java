package generic.repository;

import generic.model.EnrollmentRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This will only work in a single-node environment. When this application is load-balanced then either the
 * load-balancer must evaluate the header X-Correlation-ID for stickiness or something like Redis, Mongo or a RDBMS
 * must be used to store the enrollment data.
 */
@Component
public class InMemoryEnrollmentRepository implements EnrollmentRepository {

    private final Map<String, EnrollmentRequest> enrollments = new ConcurrentHashMap<>();

    @Override
    public String addEnrollmentRequest(EnrollmentRequest enrollmentRequest) {
        String identifier = UUID.randomUUID().toString();
        enrollmentRequest.setCreated(Instant.now());
        enrollments.put(identifier, enrollmentRequest);
        return identifier;
    }

    @Override
    public EnrollmentRequest findEnrollmentRequest(String identifier) {
        EnrollmentRequest enrollmentRequest = enrollments.get(identifier);
        if (enrollmentRequest == null) {
            throw new ExpiredEnrollmentRequestException();
        }
        return enrollmentRequest;
    }

    @Override
    public void addAccessToken(String identifier, String accessToken) {
        EnrollmentRequest enrollmentRequest = findEnrollmentRequest(identifier);
        enrollmentRequest.setAccessToken(accessToken);
    }

    @Override
    public void removeEnrollmentRequest(String identifier) {
        enrollments.remove(identifier);
    }

    @Scheduled(fixedDelayString = "${cron.fixedDelayMilliseconds}", initialDelayString= "${cron.initialDelayMilliseconds}")
    public void cleanUpEnrollments() {
        //lifetime of enrollments is 1 hour
        Instant oneHourBefore = Instant.now().minus(1L, ChronoUnit.HOURS);
        enrollments.entrySet().removeIf(entry -> entry.getValue().getCreated().isBefore(oneHourBefore));
    }


}
