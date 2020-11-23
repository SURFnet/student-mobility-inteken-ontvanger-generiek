package generic.api;

import generic.model.EnrollmentRequest;
import io.micrometer.core.instrument.util.IOUtils;
import lombok.val;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

import java.io.IOException;

@RestController
public class EnrollmentEndpoint {


    @PostMapping(value = "/enrollment", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public View enrollment(@ModelAttribute EnrollmentRequest enrollmentRequest) throws IOException {
        enrollmentRequest.validate();
        //Start
        return new RedirectView(enrollmentRequest.getReturnTo().toString());
    }

    @GetMapping("/redirect")
    public View redirect() {
        //Exchange code for access_token
    }
}
