package generic.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.net.URI;
import java.util.Map;

@NoArgsConstructor
@Getter
@Setter
public class EnrollmentRequest implements Serializable {

    private URI offeringURI;
    private URI personURI;
    private String scope;
    private URI returnTo;

    private String accessToken;

    public void validate() {
        Assert.notNull(offeringURI, "offeringURI is required");
        Assert.notNull(personURI, "personURI is required");
        Assert.notNull(scope, "scope is required");
        Assert.notNull(returnTo, "returnTo is required");
    }

}
