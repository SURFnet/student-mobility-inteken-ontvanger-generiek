package generiek.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import java.io.Serializable;
import java.time.Instant;

/**
 * Student-supplied personal details (naam, adres, e-mail, telefoon, opleiding, studentnummer bij eigen
 * instelling) that were missing from the home institution's OOAPI person response and were filled in by
 * the student through the generiek client, so they can be reused for the rest of the enrollment flow
 * (e.g. the customAgreement).
 */
@Entity(name = "student_details")
@NoArgsConstructor
@Getter
@Setter
@ToString(exclude = {"enrollmentRequest"})
public class StudentDetails implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "enrollment_request_id", nullable = false, unique = true)
    private EnrollmentRequest enrollmentRequest;

    @Column
    private String naam;

    @Column
    private String adres;

    @Column
    private String email;

    @Column
    private String telefoon;

    @Column
    private String opleiding;

    @Column
    private String studentnummer;

    @Column
    private Instant created;

    public StudentDetails(EnrollmentRequest enrollmentRequest) {
        this.enrollmentRequest = enrollmentRequest;
        this.created = Instant.now();
    }

}
