package generiek;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class LanguageFilterTest {

    @Test
    void doFilter() throws ServletException, IOException {
        LanguageFilter filter = new LanguageFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.ACCEPT_LANGUAGE, "nl-NL");
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertEquals("nl-NL",LanguageFilter.language.get());
    }
}