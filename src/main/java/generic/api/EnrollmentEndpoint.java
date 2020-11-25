package generic.api;

import generic.model.EnrollmentRequest;
import generic.model.ExtendedOidcUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@RestController
public class EnrollmentEndpoint {

    public static final String ENROLLMENT_REQUEST_SESSION_KEY = "ENROLLMENT_REQUEST_SESSION_KEY";

    private final URI backendUrl;
    private final String backendApiUser;
    private final String backendApiPassword;
    private final String clientUrl;
    private final RestTemplate restTemplate;

    public EnrollmentEndpoint(@Value("${backend.url}") URI backendUrl,
                              @Value("${backend.api_user}") String backendApiUser,
                              @Value("${backend.api_password}") String backendApiPassword,
                              @Value("${client_url}") String clientUrl) {
        this.backendUrl = backendUrl;
        this.backendApiUser = backendApiUser;
        this.backendApiPassword = backendApiPassword;
        this.clientUrl = clientUrl;
        this.restTemplate = new RestTemplate();
    }

    /*
     * Endpoint called by the student-mobility-broker form submit
     */
    @PostMapping(value = "/enrollment", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public View enrollment(HttpServletRequest request, @ModelAttribute EnrollmentRequest enrollmentRequest) throws IOException {
        enrollmentRequest.validate();
        request.getSession().setAttribute(ENROLLMENT_REQUEST_SESSION_KEY, enrollmentRequest);
        //Start authorization flow using Spring - no manually redirect
        return new RedirectView("/callback");
    }

    /*
     * Callback after authentication. Give browser-control back to the client to call start and show progress-spinner
     */
    @GetMapping("/callback")
    public View callback() {
        return new RedirectView(clientUrl, clientUrl.startsWith("/"));
    }

    /*
     * Called by the client to display user and course information
     */
    @GetMapping("/me")
    public Map<String, Object> me(HttpServletRequest request, Authentication authentication) {
        ExtendedOidcUser oidcUser = (ExtendedOidcUser) authentication.getPrincipal();
        EnrollmentRequest enrollmentRequest = (EnrollmentRequest) request.getSession().getAttribute(ENROLLMENT_REQUEST_SESSION_KEY);
        Map<String, Object> result = new HashMap<>();

        Map offering = restTemplate.getForEntity(enrollmentRequest.getOffering(), Map.class).getBody();
        result.put("offering", offering);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Accept", "application/json, application/json;charset=UTF-8");
        httpHeaders.add("Authorization", "Bearer " + oidcUser.getAccessToken().getTokenValue());
        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(httpHeaders);
        Map person = restTemplate.exchange(enrollmentRequest.getPerson(), HttpMethod.GET, requestEntity, Map.class).getBody();
        result.put("person", person);
        return result;
    }

    /*
     * Start the actual enrollment based on the data returned in the me endpoint
     */
    @PostMapping("/start")
    public Map<String, Object> start(@RequestBody Map<String, Object> body) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBasicAuth(backendApiUser, backendApiPassword);
        HttpEntity<Map<String, Object>> httpEntity = new HttpEntity<>(body, httpHeaders);
        ResponseEntity<Map> responseEntity = restTemplate.exchange(backendUrl, HttpMethod.POST, httpEntity, Map.class);
        return responseEntity.getBody();
    }

}
