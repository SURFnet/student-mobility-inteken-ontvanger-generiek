package generiek.api;

import io.swagger.v3.oas.annotations.Operation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class FeaturesController {

    private final String catalogUrl;
    private final String brokerUrl;

    public FeaturesController(@Value("${config.catalog_url}") String catalogUrl,
                              @Value("${broker.url}") String brokerUrl) {
        this.catalogUrl = catalogUrl;
        this.brokerUrl = brokerUrl;
    }

    @Operation(summary = "Get feature toggles", description = "Returns the feature toggles / config the client needs to render.")
    @CrossOrigin(origins = "${client.url}")
    @GetMapping("/api/features")
    public Map<String, Object> features() {
        return Map.of("catalogUrl", catalogUrl, "brokerUrl", brokerUrl);
    }

}
