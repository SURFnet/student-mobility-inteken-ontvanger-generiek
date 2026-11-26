package generiek.api;

import io.swagger.v3.oas.annotations.Operation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

@RestController
public class EducationItemNames {
	private final ObjectMapper objectMapper = new ObjectMapper();

	@Value("file:data/educationItemNames.json")
	private Resource educationItemNamesResource;
	private String[] educationItemNamesArray;

	private String[] loadEducationItemNames() {
		if (educationItemNamesResource.exists() && educationItemNamesResource.isReadable()) {
			try {
				return objectMapper.readValue(educationItemNamesResource.getInputStream(), String[].class);
			} catch (IOException e) {
				// Logging...
				e.printStackTrace();

			}
		}
		return new String[0];

	}

	@Operation(summary = "Get educationItemNames", description = "Returns array of educationItemNames")
	@CrossOrigin(origins = "${client.url}")
	@GetMapping("/api/educationItemNames")
	public String[] educationItemNames() {
		if(educationItemNamesArray == null)
		{
			educationItemNamesArray = loadEducationItemNames();
		}
		return educationItemNamesArray;
	}

}
