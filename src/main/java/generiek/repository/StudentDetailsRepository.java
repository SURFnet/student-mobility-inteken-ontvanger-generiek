package generiek.repository;

import generiek.model.EnrollmentRequest;
import generiek.model.StudentDetails;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface StudentDetailsRepository extends CrudRepository<StudentDetails, Long> {

    Optional<StudentDetails> findByEnrollmentRequest(EnrollmentRequest enrollmentRequest);

}
