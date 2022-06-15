package generiek.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.IOUtils;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.util.Assert;

import javax.persistence.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.*;
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

    @Column(name = "home_institution")
    private String homeInstitution;

    @Column(name = "person_auth")
    private String personAuth;

    @OneToMany(mappedBy = "enrollmentRequest", orphanRemoval = true)
    @JsonIgnore
    private Set<Association> associations = new HashSet<>();

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
        this.personAuth = enrollmentRequest.personAuth;
        this.homeInstitution = enrollmentRequest.homeInstitution;
        this.scope = enrollmentRequest.scope;
        this.setIdentifier(UUID.randomUUID().toString());
        this.setCreated(Instant.now());
    }

    private void validate(EnrollmentRequest enrollmentRequest) {
        Assert.notNull(enrollmentRequest.personURI, "personURI is required");
        Assert.notNull(enrollmentRequest.personAuth, "personAuth is required");
        Assert.notNull(enrollmentRequest.homeInstitution, "homeInstitution is required");
        Assert.notNull(enrollmentRequest.scope, "scope is required");
    }

    public String serializeToBase64(ObjectMapper objectMapper) throws IOException {
        Map<String, String> result = new HashMap<>();
        result.put("a", this.personAuth);
        result.put("h", this.homeInstitution);
        result.put("p", this.personURI);
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
        enrollmentRequest.setPersonAuth(map.get("a"));
        enrollmentRequest.setHomeInstitution(map.get("h"));
        enrollmentRequest.setPersonURI(map.get("p"));
        enrollmentRequest.setScope(map.get("s"));
        enrollmentRequest.setIdentifier(UUID.randomUUID().toString());
        enrollmentRequest.setCreated(Instant.now());

        enrollmentRequest.validate(enrollmentRequest);

        return enrollmentRequest;
    }

}
