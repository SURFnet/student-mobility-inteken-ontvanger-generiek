package generiek.repository;

import generiek.model.EnrollmentRequest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryEnrollmentRepositoryTest {

    private final InMemoryEnrollmentRepository subject = new InMemoryEnrollmentRepository();

    @Test
    void cleanUpEnrollments() {
        String identifier = subject.addEnrollmentRequest(new EnrollmentRequest());
        subject.findEnrollmentRequest(identifier).setCreated(Instant.now().minus(1L, ChronoUnit.DAYS));
        subject.cleanUpEnrollments();
        assertThrows(ExpiredEnrollmentRequestException.class, () -> subject.findEnrollmentRequest(identifier));
    }
}