package generiek.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.IOUtils;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.util.Assert;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

@Entity(name = "enrollment_requests")
@NoArgsConstructor
@Getter
@Setter
@ToString
public class EnrollmentRequest implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String identifier;

    @Column(name = "person_uri")
    private String personURI;

    @Column(name = "results_uri")
    private String resultsURI;

    @Column
    private String eduid;

    @Column
    private String accessToken;

    @Column
    private String refreshToken;

    @Column
    private String scope;

    @Column
    private Instant created;

    public EnrollmentRequest(EnrollmentRequest enrollmentRequest) {
        validate(enrollmentRequest);
        this.personURI = enrollmentRequest.personURI;
        this.resultsURI = enrollmentRequest.resultsURI;
        this.scope = enrollmentRequest.scope;
        this.setIdentifier(UUID.randomUUID().toString());
        this.setCreated(Instant.now());
    }

    private void validate(EnrollmentRequest enrollmentRequest) {
        Assert.notNull(enrollmentRequest.personURI, "personURI is required");
        Assert.notNull(enrollmentRequest.resultsURI, "resultsURI is required");
        Assert.notNull(enrollmentRequest.scope, "scope is required");
    }

    public String serializeToBase64(ObjectMapper objectMapper) throws IOException {
        Map<String, String> result = new HashMap<>();
        result.put("p", this.personURI);
        result.put("r", this.resultsURI);
        result.put("s", this.scope);
        byte[] bytes = objectMapper.writeValueAsBytes(result);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        GZIPOutputStream gout = new GZIPOutputStream(bos);
        gout.write(bytes);
        gout.finish();

        return URLEncoder.encode(Base64.getEncoder().encodeToString(bos.toByteArray()), Charset.defaultCharset().name()) ;
    }

    public static EnrollmentRequest serializeFromBase64(ObjectMapper objectMapper, String base64) throws IOException {
        byte[] decoded = Base64.getDecoder().decode(URLDecoder.decode(base64, Charset.defaultCharset().name()));
        ByteArrayInputStream bis = new ByteArrayInputStream(decoded);
        GZIPInputStream gin = new GZIPInputStream(bis);
        String json = IOUtils.readInputStreamToString(gin);

        Map<String, String> map = objectMapper.readValue(json, Map.class);

        EnrollmentRequest enrollmentRequest = new EnrollmentRequest();
        enrollmentRequest.setPersonURI(map.get("p"));
        enrollmentRequest.setResultsURI(map.get("r"));
        enrollmentRequest.setScope(map.get("s"));
        enrollmentRequest.setIdentifier(UUID.randomUUID().toString());
        enrollmentRequest.setCreated(Instant.now());

        enrollmentRequest.validate(enrollmentRequest);

        return enrollmentRequest;
    }

}
