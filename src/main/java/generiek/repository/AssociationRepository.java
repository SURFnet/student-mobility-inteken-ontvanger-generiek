package generiek.repository;

import generiek.model.Association;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * This will only work in a single-node environment. When this application is load-balanced then we need to
 * store the associations data in a distributed database like MySQL or PostgreSQL.
 */
@Repository
public interface AssociationRepository extends CrudRepository<Association, Long> {

    Optional<Association> findByAssociationId(String value);
}
