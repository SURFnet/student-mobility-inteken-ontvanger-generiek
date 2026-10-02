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
import java.time.LocalDate;

/**
 * Module and institution data needed for the CustomAgreement PDF, supplied by the broker (the only
 * party that has the offering data) at /api/enrollment time and carried through the OIDC round-trip
 * (see EnrollmentRequest's transient fields and (de)serializeToBase64), then persisted here once the
 * EnrollmentRequest itself is saved in EnrollmentEndpoint.redirect().
 */
@Entity(name = "custom_agreement_details")
@NoArgsConstructor
@Getter
@Setter
@ToString(exclude = {"enrollmentRequest"})
public class CustomAgreementDetails implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "enrollment_request_id", nullable = false, unique = true)
    private EnrollmentRequest enrollmentRequest;

    @Column
    private String moduleNaam;

    @Column
    private String moduleCode;

    @Column
    private LocalDate onderwijsperiodeStart;

    @Column
    private LocalDate onderwijsperiodeEind;

    @Column
    private String thuisinstellingNaam;

    @Column
    private String gastinstellingNaam;

    @Column
    private Instant created;

    public CustomAgreementDetails(EnrollmentRequest enrollmentRequest) {
        this.enrollmentRequest = enrollmentRequest;
        this.created = Instant.now();
    }

}
