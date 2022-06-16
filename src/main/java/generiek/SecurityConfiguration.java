package generiek;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableScheduling
@EnableWebSecurity
public class SecurityConfiguration {

    @Order(1)
    @Configuration
    public static class BrokerSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Value("${broker.user}")
        private String brokerUser;

        @Value("${broker.password}")
        private String brokerPassword;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.requestMatchers()
                    .antMatchers("/api/start")
                    .and()
                    .csrf()
                    .disable()
                    .authorizeRequests()
                    .anyRequest()
                    .authenticated()
                    .and()
                    .httpBasic()
                    .and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                    .inMemoryAuthentication()
                    .withUser(brokerUser)
                    .password("{noop}" + brokerPassword)
                    .roles("BROKER");
        }

    }

    @Order
    @Configuration
    public static class SISSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Value("${sis.user}")
        private String sisUser;

        @Value("${sis.password}")
        private String sisPassword;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.requestMatchers()
                    .antMatchers("/api/results","/api/play-results", "/associations/**")
                    .and()
                    .csrf()
                    .disable()
                    .authorizeRequests()
                    .anyRequest()
                    .authenticated()
                    .and()
                    .httpBasic()
                    .and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                    .inMemoryAuthentication()
                    .withUser(sisUser)
                    .password("{noop}" + sisPassword)
                    .roles("BROKER");
        }

    }
}