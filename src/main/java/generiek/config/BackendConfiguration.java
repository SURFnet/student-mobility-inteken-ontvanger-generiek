package generiek.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.net.URI;

@Component
@ConfigurationProperties(prefix = "backend")
public class BackendConfiguration {

    private URI url;
    private String authenticationType = "basic";
    private String apiUser;
    private String apiPassword;
    private URI oidcAuthorizationUri;
    private String oidcClientId;
    private String oidcClientSecret;
    private String oidcScope;

    public URI getUrl() {
        return url;
    }

    public void setUrl(URI url) {
        this.url = url;
    }

    public String getAuthenticationType() {
        return authenticationType;
    }

    public void setAuthenticationType(String authenticationType) {
        this.authenticationType = authenticationType;
    }

    public String getApiUser() {
        return apiUser;
    }

    public void setApiUser(String apiUser) {
        this.apiUser = apiUser;
    }

    public String getApiPassword() {
        return apiPassword;
    }

    public void setApiPassword(String apiPassword) {
        this.apiPassword = apiPassword;
    }

    public URI getOidcAuthorizationUri() {
        return oidcAuthorizationUri;
    }

    public void setOidcAuthorizationUri(URI oidcAuthorizationUri) {
        this.oidcAuthorizationUri = oidcAuthorizationUri;
    }

    public String getOidcClientId() {
        return oidcClientId;
    }

    public void setOidcClientId(String oidcClientId) {
        this.oidcClientId = oidcClientId;
    }

    public String getOidcClientSecret() {
        return oidcClientSecret;
    }

    public void setOidcClientSecret(String oidcClientSecret) {
        this.oidcClientSecret = oidcClientSecret;
    }

    public String getOidcScope() {
        return oidcScope;
    }

    public void setOidcScope(String oidcScope) {
        this.oidcScope = oidcScope;
    }
}
