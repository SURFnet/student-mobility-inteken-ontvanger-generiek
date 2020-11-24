package generic.api;

import generic.model.EnrollmentRequest;
import io.micrometer.core.instrument.util.IOUtils;
import lombok.val;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@RestController
public class EnrollmentEndpoint {


    @PostMapping(value = "/enrollment", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public View enrollment(HttpServletRequest request, @ModelAttribute EnrollmentRequest enrollmentRequest) throws IOException {
        enrollmentRequest.validate();

        //TODO deserialize the enrollmentRequest and add it as query param to "/me"- configure app to be stateless
        request.getSession().setAttribute("enrollmentRequest", enrollmentRequest);
        //Start authorization flow using Spring - no manually redirect
        return new RedirectView("/me");
    }

    @GetMapping("/me")
    public View me(HttpServletRequest request, Authentication authentication) {
        //Exchange code for access_token
        Object enrollmentRequest = request.getSession().getAttribute("enrollmentRequest");
        //TODO - call the home institution, then the configured specific intake app and return with the  results
        return new RedirectView("https://www.google.com", false);
    }
}
