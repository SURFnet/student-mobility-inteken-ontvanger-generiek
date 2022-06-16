package generiek.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;
import java.io.Serializable;
import java.time.Instant;


@Entity(name = "associations")
@NoArgsConstructor
@Getter
@Setter
@ToString(exclude = {"enrollmentRequest"})
public class Association implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "association_id")
    private String associationId;

    @Column
    private Instant created;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "enrollment_request_id")
    private EnrollmentRequest enrollmentRequest;

    public Association(String associationId, EnrollmentRequest enrollmentRequest) {
        this.associationId = associationId;
        this.enrollmentRequest = enrollmentRequest;
        this.created = Instant.now();
    }
}
