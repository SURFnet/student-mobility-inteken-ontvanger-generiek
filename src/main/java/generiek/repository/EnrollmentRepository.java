package generiek.repository;

import generiek.model.EnrollmentRequest;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * This will only work in a single-node environment. When this application is load-balanced then we need to
 * store the enrollment data in a distributed database like MySQL or PostgreSQL.
 */
@Repository
public interface EnrollmentRepository extends CrudRepository<EnrollmentRequest, Long> {

    Optional<EnrollmentRequest> findByIdentifier(String identifier);

    Optional<EnrollmentRequest> findByOfferingIdAndPersonId(String offeringId, String personId);

}
