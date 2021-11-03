package generiek;

import generiek.model.EnrollmentRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

@Component
public class ServiceRegistry {

    private final String serviceRegistryBaseURL;
    private final RestTemplate restTemplate = new RestTemplate();

    public ServiceRegistry(@Value("${broker.service_registry_base_url}") String serviceRegistryBaseURL) {
        this.serviceRegistryBaseURL = serviceRegistryBaseURL;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Boolean> validate(EnrollmentRequest enrollmentRequest) {
        return restTemplate.postForEntity(
                this.serviceRegistryBaseURL + "/api/validate-service-registry-endpoints",
                new HttpEntity<>(enrollmentRequest),
                Map.class).getBody();
    }

    @SuppressWarnings("unchecked")
    public String resultsURI(EnrollmentRequest enrollmentRequest) {
        Map<String, String> results = restTemplate.postForEntity(
                this.serviceRegistryBaseURL + "/api/results-uri",
                new HttpEntity<>(Collections.singletonMap("homeInstitution", enrollmentRequest.getHomeInstitution())),
                Map.class).getBody();
        return results.get("resultsURI");
    }

    public String getServiceRegistryBaseURL() {
        return serviceRegistryBaseURL;
    }
}
