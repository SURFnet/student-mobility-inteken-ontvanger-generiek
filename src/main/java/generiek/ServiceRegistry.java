package generiek;

import generiek.model.EnrollmentRequest;
import okhttp3.OkHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.client.OkHttp3ClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
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
        return restTemplate.postForEntity(
                this.serviceRegistryBaseURL + "/api/validate-service-registry-endpoints",
                new HttpEntity<>(enrollmentRequest),
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
