package generic.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.*;

class JWTValidatorTest {

    private JWTValidator subject = new JWTValidator();

    @Test
    void validate() {
        assertThrows(ParseException.class, () -> subject.validate("nope", subject.parseKeySet("http://localhost")));
    }

    @Test
    void parseKeySet() {
        assertThrows(IOException.class, () -> subject.parseKeySet("nope"));
    }
}