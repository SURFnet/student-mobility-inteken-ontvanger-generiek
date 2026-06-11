package generiek;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class GenericApplication {
    public static final String CacheName = "application";

    public static void main(String[] args) {
        SpringApplication.run(GenericApplication.class, args);

    }

}
