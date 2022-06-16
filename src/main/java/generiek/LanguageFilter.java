package generiek;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Component
@Order(1)
public class LanguageFilter implements Filter {

    public static ThreadLocal<String> language = new ThreadLocal<>();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String languageHeader = ((HttpServletRequest) request).getHeader("Accept-Language");
        language.set(StringUtils.hasText(languageHeader) ? languageHeader : "en-GB");
        chain.doFilter(request, response);
    }
}
