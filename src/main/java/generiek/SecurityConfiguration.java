package generiek;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableScheduling
@EnableWebSecurity
public class SecurityConfiguration {

    @Value("${broker.user}")
    private String brokerUser;

    @Value("${broker.password}")
    private String brokerPassword;

    @Value("${sis.user}")
    private String sisUser;

    @Value("${sis.password}")
    private String sisPassword;

    @Order(1)
    @Bean
    public SecurityFilterChain brokerSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/start")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationManager(authenticationManager(brokerUser, brokerPassword));

        return http.build();
    }

    @Order(2)
    @Bean
    public SecurityFilterChain sisSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(
                        "/api/results",
                        "/associations/**",
                        "/api/play-results",
                        "/api/me",
                        "/person/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationManager(authenticationManager(sisUser, sisPassword));

        return http.build();
    }

    private AuthenticationManager authenticationManager(String user, String password) {
        InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager(
                User.withUsername(user)
                        .password("{noop}" + password)
                        .roles("BROKER")
                        .build());

        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);

        return new ProviderManager(authenticationProvider);
    }
}
