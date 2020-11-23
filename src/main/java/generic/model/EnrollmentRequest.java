package generic.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.util.Assert;

import java.net.URI;

@NoArgsConstructor
@Getter
@Setter
public class EnrollmentRequest {

    private URI offering;
    private URI person;
    private String scope;
    private URI returnTo;

    public void validate() {
        Assert.notNull(offering, "offering is required");
        Assert.notNull(person, "person is required");
        Assert.notNull(scope, "scope is required");
        Assert.notNull(returnTo, "returnTo is required");
    }
}
