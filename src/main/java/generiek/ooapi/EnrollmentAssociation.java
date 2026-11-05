package generiek.ooapi;

import generiek.model.EnrollmentRequest;
import org.springframework.util.StringUtils;

import java.util.HashMap;
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
        addAllianceConsumer(results, enrollmentRequest);
        return results;
    }

    @SuppressWarnings("unchecked")
    public static void addAllianceConsumer(Map<String, Object> body, EnrollmentRequest enrollmentRequest) {
        if (!StringUtils.hasText(enrollmentRequest.getAlliance())) {
            return;
        }
        Map<String, Object> consumers = (Map<String, Object>) body.computeIfAbsent("consumers", key -> new HashMap<String, Object>());
        Map<String, Object> alliance = new HashMap<>();
        alliance.put("name", enrollmentRequest.getAlliance());
        consumers.put("alliance", alliance);
    }

}
