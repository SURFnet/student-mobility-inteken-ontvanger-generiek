package generic.security;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.servlet.http.HttpServletRequest;

public class OidcCorsConfigurationSource implements CorsConfigurationSource {

    @Override
    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.addAllowedOriginPattern("http://*");
        corsConfiguration.addAllowedOriginPattern("https://*");
        corsConfiguration.applyPermitDefaultValues();
        corsConfiguration.setAllowCredentials(true);
        return corsConfiguration;
    }
}
