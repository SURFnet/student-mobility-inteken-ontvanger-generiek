package generiek.repository;

import generiek.model.CustomAgreementDetails;
import generiek.model.EnrollmentRequest;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CustomAgreementDetailsRepository extends CrudRepository<CustomAgreementDetails, Long> {

    Optional<CustomAgreementDetails> findByEnrollmentRequest(EnrollmentRequest enrollmentRequest);

}
