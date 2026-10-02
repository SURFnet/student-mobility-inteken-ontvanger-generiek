package generiek.api;

import com.nimbusds.jose.util.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.stream.Collectors;

public class RestTemplateLoggingInterceptor implements ClientHttpRequestInterceptor {

    private static final Log LOG = LogFactory.getLog(RestTemplateLoggingInterceptor.class);

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        // Log request details
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Start sending HttpRequest: URI:%s, Headers: (%s), Method: %s, Body: %s",
                    request.getURI(),
                    this.headersToString(request.getHeaders()),
                    request.getMethod(),
                    new String(body, Charset.defaultCharset())));
        }
        // Execute the request
        ClientHttpResponse response = execution.execute(request, body);
        if (LOG.isDebugEnabled()) {
            // Log response details
            LOG.debug(String.format("Received response: StatusCode:%s, Headers:%s, Body:%s",
                    response.getStatusCode(),
                    this.headersToString(response.getHeaders()),
                    IOUtils.readInputStreamToString(response.getBody())
            ));
        }
        return response;
    }

    private String headersToString(HttpHeaders headers) {
        return headers.entrySet().stream()
                .map(entry -> String.format("%s:%s", entry.getKey(), String.join(", ", entry.getValue())))
                .collect(Collectors.joining(";"));
    }
}


