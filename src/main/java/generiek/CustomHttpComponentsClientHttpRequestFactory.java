package generiek;

import org.springframework.http.client.SimpleClientHttpRequestFactory;

public class CustomHttpComponentsClientHttpRequestFactory extends SimpleClientHttpRequestFactory {

    public CustomHttpComponentsClientHttpRequestFactory(int connectionTimeoutMillis) {
        super.setConnectTimeout(connectionTimeoutMillis);
        super.setReadTimeout(connectionTimeoutMillis);
    }
}
