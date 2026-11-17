package generiek;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

@Component
@Order(1)
public class LanguageFilter implements Filter {

    public static ThreadLocal<String> language = new ThreadLocal<>();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String languageHeader = ((HttpServletRequest) request).getHeader(HttpHeaders.ACCEPT_LANGUAGE);
        language.set(StringUtils.hasText(languageHeader) ? languageHeader : "en-GB");
        chain.doFilter(request, response);
    }
}
