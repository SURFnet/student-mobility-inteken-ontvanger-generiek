package generiek.ooapi;

import generiek.model.EnrollmentRequest;

import java.util.Map;

/**
 * Responsible for the transformation of the association reported back from the SIS to the OOAPI format.
 */
public class EnrollmentAssociation {

    private EnrollmentAssociation() {
    }

    public static Map<String, Object> transform(Map<String, Object> results, EnrollmentRequest enrollmentRequest) {
        //For now assume we can leave everything as is, but this is not very feasible for the actual implementation
        results.put("personId", enrollmentRequest.getEduid());
        return results;
    }

}
