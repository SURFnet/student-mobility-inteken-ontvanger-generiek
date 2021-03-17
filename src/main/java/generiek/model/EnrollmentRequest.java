package generiek.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.util.Assert;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

@Entity(name = "enrollment_requests")
@NoArgsConstructor
@Getter
@Setter
@ToString
public class EnrollmentRequest implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String identifier;

    @Column(name = "person_uri")
    private String personURI;

    @Column
    private String personId;

    @Column
    private String offeringId;

    @Column
    private String accessToken;

    @Column
    private String refreshToken;

    @Column
    private String scope;

    @Column
    private Instant created;

    public EnrollmentRequest(EnrollmentRequest enrollmentRequest) {
        validate(enrollmentRequest);
        this.personURI = enrollmentRequest.personURI;
        this.scope = enrollmentRequest.scope;
        this.identifier = UUID.randomUUID().toString();
        this.created = Instant.now();
    }

    private void validate(EnrollmentRequest enrollmentRequest) {
        Assert.notNull(enrollmentRequest.personURI, "personURI is required");
        Assert.notNull(enrollmentRequest.scope, "scope is required");
    }

}
