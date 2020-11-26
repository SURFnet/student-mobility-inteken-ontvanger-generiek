package generic.security;

import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.apache.tomcat.util.http.SameSiteCookies;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CookieConfiguration {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> sessionManagerCustomizer() {
        return server -> {
            Rfc6265CookieProcessor rfc6265Processor = new Rfc6265CookieProcessor();
            rfc6265Processor.setSameSiteCookies(SameSiteCookies.NONE.getValue());
            server.addContextCustomizers(context -> context.setCookieProcessor(rfc6265Processor));
        };
    }

}

