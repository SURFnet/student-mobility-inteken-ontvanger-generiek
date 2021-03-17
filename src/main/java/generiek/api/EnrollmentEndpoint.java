package generiek.api;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import generiek.jwt.JWTValidator;
import generiek.model.EnrollmentRequest;
import generiek.repository.EnrollmentRepository;
import generiek.repository.ExpiredEnrollmentRequestException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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
    private final RestTemplate restTemplate = new RestTemplate();
    private final EnrollmentRepository enrollmentRepository;
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
        this.enrollmentRepository = enrollmentRepository;
    }

    /*
     * Endpoint called by the student-mobility-broker form submit
     */
    @PostMapping(value = "/api/enrollment", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public View enrollment(@ModelAttribute EnrollmentRequest enrollmentRequest) {
        LOG.debug("Received authorization for enrollment request: " + enrollmentRequest.toString());
        // Prevent forgery and cherry-pick attributes
        enrollmentRequest = new EnrollmentRequest(enrollmentRequest);
        enrollmentRepository.save(enrollmentRequest);
        String identifier = enrollmentRequest.getIdentifier();
        //Start authorization flow
        String authorizationURI = this.buildAuthorizationURI(identifier, enrollmentRequest);

        LOG.debug("Starting authorization for enrollment");

        return new RedirectView(authorizationURI);
    }

    /*
     * Redirect after authentication. Give browser-control back to the client to call start and show progress-spinner
     */
    @GetMapping("/redirect_uri")
    public View redirect(@RequestParam("code") String code, @RequestParam("state") String state) throws ParseException, UnsupportedEncodingException {
        LOG.debug("Redirect after authorization called");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("client_secret", clientSecret);
        map.add("code", code);
        map.add("grant_type", "authorization_code");
        map.add("redirect_uri", redirectUri);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        Map<String, Object> body = restTemplate.exchange(tokenUri, HttpMethod.POST, request, new ParameterizedTypeReference<Map<String, Object>>() {
        }).getBody();

        String accessToken = (String) body.get("access_token");
        String refreshToken = (String) body.get("refresh_token");
        String idToken = (String) body.get("id_token");

        JWKSource<SecurityContext> securityContextJWKSource = jwtValidator.parseKeySet(jwkSetUri);
        jwtValidator.validate(accessToken, securityContextJWKSource);
        JWTClaimsSet claimsSet = jwtValidator.validate(idToken, securityContextJWKSource);

        String givenName = claimsSet.getStringClaim("given_name");
        if (!StringUtils.hasText(givenName)) {
            throw new IllegalArgumentException("No given_name in claim set");
        }
        givenName = URLEncoder.encode(givenName, "UTF-8");
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(state)
                .orElseThrow(ExpiredEnrollmentRequestException::new);

        enrollmentRequest.setAccessToken(accessToken);
        enrollmentRequest.setRefreshToken(refreshToken);
        enrollmentRepository.save(enrollmentRequest);

        String redirect = String.format("%s?step=enroll&correlationID=%s&name=%s", brokerUrl, state, givenName);

        LOG.debug(String.format("Redirecting back to %s client after authorization", redirect));

        return new RedirectView(redirect, false);
    }

    /*
     * Start the actual enrollment based on the data returned in the me endpoint
     */
    @PostMapping("/api/start")
    public Map<String, Object> start(
            @RequestHeader("X-Correlation-ID") String correlationId,
            @RequestBody Map<String, Object> offering) {
        LOG.debug("Received start registration from broker for correlationId: " + correlationId);

        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId)
                .orElseThrow(ExpiredEnrollmentRequestException::new);

        Map<String, Map<String, Object>> body = new HashMap<>();
        body.put("offering", offering);
        Map<String, Object> personMap = person(enrollmentRequest);
        body.put("person", personMap);

        //Save the offering, person and refreshToken in a persistent DB
        enrollmentRequest.setOfferingId((String) offering.get("offeringId"));
        enrollmentRequest.setPersonId((String) personMap.get("personId"));
        enrollmentRepository.save(enrollmentRequest);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBasicAuth(backendApiUser, backendApiPassword);
        HttpEntity<Map<String, Object>> httpEntity = new HttpEntity(body, httpHeaders);
        ResponseEntity<Map<String, Object>> responseEntity = restTemplate.exchange(backendUrl, HttpMethod.POST, httpEntity, mapRef);

        LOG.debug("Returning registration result to broker");

        return responseEntity.getBody();
    }

    private Map<String, Object> person(EnrollmentRequest enrollmentRequest) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Accept", "application/json, application/json;charset=UTF-8");
        httpHeaders.add("Authorization", "Bearer " + enrollmentRequest.getAccessToken());
        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(httpHeaders);
        LOG.debug("Retrieve person information from : " + enrollmentRequest.getPersonURI());
        return restTemplate.exchange(enrollmentRequest.getPersonURI(), HttpMethod.GET, requestEntity, mapRef).getBody();
    }

    private String buildAuthorizationURI(String state, EnrollmentRequest enrollmentRequest) {
        Map<String, String> params = new HashMap<>();

        List<ClaimsSetRequest.Entry> entries = Stream.of(
                "family_name",
                "given_name"
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


}