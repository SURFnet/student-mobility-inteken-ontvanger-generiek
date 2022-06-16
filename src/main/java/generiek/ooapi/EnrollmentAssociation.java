package generiek.ooapi;

import java.util.Map;

/**
 * Responsible for the transformation of the association reported back from the SIS to the OOAPI format.
 */
public class EnrollmentAssociation {

    private final Map<String, Object> results;

    public EnrollmentAssociation(Map<String, Object> results) {
        this.results = results;
    }

    public Map<String, Object> transform() {
        //For now assume we can leave everything as is, but this is not very feasible for the actual implementation
        this.results.remove("personId");
        return this.results;
    }

}
