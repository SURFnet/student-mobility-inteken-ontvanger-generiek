package generiek.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.net.URI;
import java.time.Instant;

@NoArgsConstructor
@Getter
@Setter
@ToString
public class EnrollmentRequest implements Serializable {

    private URI personURI;
    private String scope;

    private String accessToken;
    private Instant created;

    public void validate() {
        Assert.notNull(personURI, "personURI is required");
        Assert.notNull(scope, "scope is required");
    }

}
