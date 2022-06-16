package generiek.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class ExpiredEnrollmentRequestException extends RuntimeException {

    public ExpiredEnrollmentRequestException() {
      super("Enrollment not found.");
    }

}
