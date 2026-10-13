package generiek;

import generiek.model.EnrollmentRequest;
import okhttp3.OkHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.client.OkHttp3ClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
public class ServiceRegistry {

    private final String serviceRegistryBaseURL;
    private final RestTemplate restTemplate;

    public ServiceRegistry(
            @Value("${broker.service_registry_base_url}") String serviceRegistryBaseURL,
            @Value("${config.connection_timeout_millis}") int connectionTimeoutMillis) {
        this.serviceRegistryBaseURL = serviceRegistryBaseURL;
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.connectTimeout(connectionTimeoutMillis, TimeUnit.MILLISECONDS);
        builder.readTimeout(connectionTimeoutMillis, TimeUnit.MILLISECONDS);
        builder.retryOnConnectionFailure(true);
        this.restTemplate = new RestTemplate(new OkHttp3ClientHttpRequestFactory(builder.build()));
    }

    @SuppressWarnings("unchecked")
    public Map<String, Boolean> validate(EnrollmentRequest enrollmentRequest) {
        //Only personURI/homeInstitution (and optionally associationsURI) are ever read on the
        //receiving end - send just those instead of the whole object, so that serializing any other
        //field on EnrollmentRequest (e.g. the LocalDate custom-agreement fields) can never break this.
        Map<String, String> body = new HashMap<>();
        body.put("personURI", enrollmentRequest.getPersonURI());
        body.put("homeInstitution", enrollmentRequest.getHomeInstitution());
        return restTemplate.postForEntity(
                this.serviceRegistryBaseURL + "/api/validate-service-registry-endpoints",
                new HttpEntity<>(body),
                Map.class).getBody();
    }

    @SuppressWarnings("unchecked")
    public String associationsURI(EnrollmentRequest enrollmentRequest) {
        Map<String, String> results = restTemplate.postForEntity(
                this.serviceRegistryBaseURL + "/api/associations-uri",
                new HttpEntity<>(Collections.singletonMap("homeInstitution", enrollmentRequest.getHomeInstitution())),
                Map.class).getBody();
        return results.get("associationsURI");
    }

    @SuppressWarnings("unchecked")
    public String personsURI(EnrollmentRequest enrollmentRequest) {
        Map<String, String> results = restTemplate.postForEntity(
                this.serviceRegistryBaseURL + "/api/persons-uri",
                new HttpEntity<>(Collections.singletonMap("homeInstitution", enrollmentRequest.getHomeInstitution())),
                Map.class).getBody();
        return results.get("personsURI");
    }

    public String getServiceRegistryBaseURL() {
        return serviceRegistryBaseURL;
    }
}
