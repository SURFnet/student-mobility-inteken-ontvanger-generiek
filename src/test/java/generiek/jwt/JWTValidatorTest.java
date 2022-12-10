package generiek.jwt;

import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertThrows;

class JWTValidatorTest {

    private final JWTValidator subject = new JWTValidator("http://localhost");

    JWTValidatorTest() throws MalformedURLException {
    }

    @Test
    void validate() {
        assertThrows(ParseException.class, () -> subject.validate("nope"));
    }
}