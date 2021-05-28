package generiek.api;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import generiek.jwt.JWTValidator;
import generiek.model.EnrollmentRequest;
import generiek.ooapi.EnrollmentResult;
import generiek.repository.EnrollmentRepository;
import generiek.repository.ExpiredEnrollmentRequestException;
import lombok.SneakyThrows;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
public class EnrollmentEndpoint {

    private static final Log LOG = LogFactory.getLog(EnrollmentEndpoint.class);

    private final String acr;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final URI authorizationUri;
    private final URI tokenUri;
    private final String jwkSetUri;
    private final URI backendUrl;
    private final String backendApiUser;
    private final String backendApiPassword;
    private final String brokerUrl;
    private final URI validationServiceRegistryEndpoint;
    private final boolean allowPlayground;
    private final EnrollmentRepository enrollmentRepository;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ParameterizedTypeReference<Map<String, Object>> mapRef = new ParameterizedTypeReference<Map<String, Object>>() {
    };
    private final JWTValidator jwtValidator = new JWTValidator();

    public EnrollmentEndpoint(@Value("${oidc.acr-context-class-ref}") String acr,
                              @Value("${oidc.client-id}") String clientId,
                              @Value("${oidc.client-secret}") String clientSecret,
                              @Value("${oidc.redirect-uri}") String redirectUri,
                              @Value("${oidc.authorization-uri}") URI authorizationUri,
                              @Value("${oidc.token-uri}") URI tokenUri,
                              @Value("${oidc.jwk-set-uri}") String jwkSetUri,
                              @Value("${backend.url}") URI backendUrl,
                              @Value("${backend.api_user}") String backendApiUser,
                              @Value("${backend.api_password}") String backendApiPassword,
                              @Value("${broker.url}") String brokerUrl,
                              @Value("${broker.validation_service_registry_endpoint}") URI validationServiceRegistryEndpoint,
                              @Value("${features.allow_playground}") boolean allowPlayground,
                              EnrollmentRepository enrollmentRepository) {
        this.acr = acr;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.authorizationUri = authorizationUri;
        this.tokenUri = tokenUri;
        this.jwkSetUri = jwkSetUri;
        this.backendUrl = backendUrl;
        this.backendApiUser = backendApiUser;
        this.backendApiPassword = backendApiPassword;
        this.brokerUrl = brokerUrl;
        this.validationServiceRegistryEndpoint = validationServiceRegistryEndpoint;
        this.enrollmentRepository = enrollmentRepository;
        this.allowPlayground = allowPlayground;
    }

    /*
     * Endpoint called by the student-mobility-broker form submit
     */
    @PostMapping(value = "/api/enrollment", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public View enrollment(@ModelAttribute EnrollmentRequest enrollmentRequest) {
        LOG.debug("Received authorization for enrollment request: " + enrollmentRequest);
        // Prevent forgery and cherry-pick attributes
        enrollmentRequest = new EnrollmentRequest(enrollmentRequest);
        // Check the broker-serviceregistry to validate the personURI and resultURI before continuing
        this.validateServiceRegistryEndpoints(enrollmentRequest);

        enrollmentRepository.save(enrollmentRequest);
        String identifier = enrollmentRequest.getIdentifier();
        //Start authorization flow
        String authorizationURI = this.buildAuthorizationURI(identifier, enrollmentRequest);

        LOG.debug("Starting authorization for enrollment request: " + enrollmentRequest);

        return new RedirectView(authorizationURI);
    }

    /*
     * Redirect after authentication. Give browser-control back to the client to call start and show progress-spinner
     */
    @GetMapping("/redirect_uri")
    public View redirect(@RequestParam("code") String code, @RequestParam("state") String state) throws ParseException, UnsupportedEncodingException {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("client_secret", clientSecret);
        map.add("code", code);
        map.add("grant_type", "authorization_code");
        map.add("redirect_uri", redirectUri);

        Map<String, Object> body = tokenRequest(map);

        String accessToken = (String) body.get("access_token");
        String refreshToken = (String) body.get("refresh_token");
        String idToken = (String) body.get("id_token");

        JWKSource<SecurityContext> securityContextJWKSource = jwtValidator.parseKeySet(jwkSetUri);
        jwtValidator.validate(accessToken, securityContextJWKSource);
        JWTClaimsSet claimsSet = jwtValidator.validate(idToken, securityContextJWKSource);

        String givenName = claimsSet.getStringClaim("given_name");
        //Very unlikely and why break on this?
        givenName = StringUtils.hasText(givenName) ? givenName : "Mystery guest";
        givenName = URLEncoder.encode(givenName, "UTF-8");

        String eduid = claimsSet.getStringClaim("eduid");
        if (!StringUtils.hasText(eduid)) {
            throw new IllegalArgumentException("eduid is required. Check the ARP for RP:" + this.clientId);
        }

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(state)
                .orElseThrow(ExpiredEnrollmentRequestException::new);

        LOG.debug("Redirect after authorization called for enrollment request: " + enrollmentRequest);

        enrollmentRequest.setEduid(eduid);
        enrollmentRequest.setAccessToken(accessToken);
        enrollmentRequest.setRefreshToken(refreshToken);
        enrollmentRepository.save(enrollmentRequest);

        String redirect = String.format("%s?step=enroll&correlationID=%s&name=%s", brokerUrl, state, givenName);

        LOG.debug(String.format("Redirecting back to %s client after authorization", redirect));

        return new RedirectView(redirect, false);
    }

    private Map<String, Object> tokenRequest(MultiValueMap<String, String> map) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        return restTemplate.exchange(tokenUri, HttpMethod.POST, request, new ParameterizedTypeReference<Map<String, Object>>() {
        }).getBody();
    }

    /*
     * Start the actual enrollment based on the data returned in the me endpoint
     */
    @PostMapping("/api/start")
    public Map<String, Object> start(
            @RequestHeader("X-Correlation-ID") String correlationId,
            @RequestBody Map<String, Object> offering) {
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId)
                .orElseThrow(ExpiredEnrollmentRequestException::new);

        LOG.debug("Received start registration from broker for enrollment request: " + enrollmentRequest);

        Map<String, Map<String, Object>> body = new HashMap<>();
        body.put("offering", offering);
        Map<String, Object> personMap = person(enrollmentRequest);
        personMap.put("personId", enrollmentRequest.getEduid());
        body.put("person", personMap);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBasicAuth(backendApiUser, backendApiPassword);
        HttpEntity<Map<String, Object>> httpEntity = new HttpEntity(body, httpHeaders);
        ResponseEntity<Map<String, Object>> responseEntity = restTemplate.exchange(backendUrl, HttpMethod.POST, httpEntity, mapRef);

        LOG.debug("Returning registration result to broker");

        return responseEntity.getBody();
    }

    /*
     * Called by the Broker on behalf of the test user
     */
    @PostMapping("/api/play-results")
    public ResponseEntity<Void> playResults(@RequestHeader("X-Correlation-ID") String correlationId, @RequestBody Map<String, Object> results) {
        if (!allowPlayground) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId).orElseThrow(ExpiredEnrollmentRequestException::new);
        Map<String, Object> newResults = new HashMap<>(results);
        newResults.put("personId", enrollmentRequest.getEduid());
        return this.results(newResults);
    }

    /*
     * Called by the SIS of the guest institution to report back results that need to be send with oauth secured
     * to the home institution
     */
    @PostMapping("/api/results")
    public ResponseEntity<Void> results(@RequestBody Map<String, Object> results) {
        String personId = (String) results.get("personId");

        List<EnrollmentRequest> enrollmentRequests = enrollmentRepository.findByEduidOrderByCreatedDesc(personId);
        if (CollectionUtils.isEmpty(enrollmentRequests)) {
            throw new ExpiredEnrollmentRequestException();
        }
        EnrollmentRequest enrollmentRequest = enrollmentRequests.get(0);

        LOG.debug(String.format("Report back results endpoint called by SIS personId %s and enrolment request %s", personId, enrollmentRequest));

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("client_secret", clientSecret);
        map.add("grant_type", "refresh_token");
        map.add("refresh_token", enrollmentRequest.getRefreshToken());

        LOG.debug("Obtaining new accessToken with saved refreshToken for enrolment request: " + enrollmentRequest);

        Map<String, Object> oidcResponse = tokenRequest(map);

        String accessToken = (String) oidcResponse.get("access_token");
        String resultsURI = enrollmentRequest.getResultsURI();

        //Now call the actual OOAPI endpoint with the new accessToken
        LOG.debug(String.format("Posting back results endpoint for personId %s and enrolment request %s to %s", personId, enrollmentRequest, resultsURI));

        HttpHeaders httpHeaders = getOidcAuthorizationHttpHeaders(accessToken);
        Map<String, Object> body = new EnrollmentResult(results).transform();
        HttpEntity<Void> requestEntity = new HttpEntity(body, httpHeaders);

        ResponseEntity<Void> exchanged = restTemplate.exchange(resultsURI, HttpMethod.POST, requestEntity, Void.class);

        LOG.debug(String.format("Received answer from %s with status %s", resultsURI, exchanged.getStatusCode()));
        //cleanup
        enrollmentRepository.deleteAll(enrollmentRequests);
        return exchanged;
    }

    private Map<String, Object> person(EnrollmentRequest enrollmentRequest) {
        HttpHeaders httpHeaders = getOidcAuthorizationHttpHeaders(enrollmentRequest.getAccessToken());
        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(httpHeaders);

        LOG.debug("Retrieve person information from : " + enrollmentRequest.getPersonURI());

        return restTemplate.exchange(enrollmentRequest.getPersonURI(), HttpMethod.GET, requestEntity, mapRef).getBody();
    }

    private HttpHeaders getOidcAuthorizationHttpHeaders(String accessToken) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Accept", "application/json, application/json;charset=UTF-8");
        httpHeaders.add("Authorization", "Bearer " + accessToken);
        return httpHeaders;
    }

    private String buildAuthorizationURI(String state, EnrollmentRequest enrollmentRequest) {
        Map<String, String> params = new HashMap<>();

        List<ClaimsSetRequest.Entry> entries = Stream.of(
                "family_name",
                "given_name",
                "eduid"
        ).map(ClaimsSetRequest.Entry::new).collect(Collectors.toList());
        params.put("claims", new OIDCClaimsRequest().withIDTokenClaimsRequest(new ClaimsSetRequest(entries)).toJSONString());

        params.put("acr_values", acr);
        params.put("scope", "openid " + enrollmentRequest.getScope());
        params.put("client_id", clientId);
        params.put("response_type", "code");
        params.put("redirect_uri", redirectUri);
        params.put("state", state);

        UriComponentsBuilder builder = UriComponentsBuilder.fromUri(authorizationUri);
        params.forEach(builder::queryParam);
        return builder.build().encode().toUriString();
    }

    @SneakyThrows
    private void validateServiceRegistryEndpoints(EnrollmentRequest enrollmentRequest) {
        ResponseEntity<Map> response = restTemplate.postForEntity(
                this.validationServiceRegistryEndpoint,
                new HttpEntity<>(enrollmentRequest),
                Map.class);
        if (!(boolean) response.getBody().get("valid")) {
            throw new IllegalArgumentException(
                    String.format("Invalid URI's for enrolment %s provided reported by %s",
                            enrollmentRequest, this.validationServiceRegistryEndpoint));
        }
    }

}
