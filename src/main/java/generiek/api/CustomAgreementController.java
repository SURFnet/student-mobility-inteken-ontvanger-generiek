package generiek.api;

import generiek.exception.ExpiredEnrollmentRequestException;
import generiek.model.EnrollmentRequest;
import generiek.model.CustomAgreementDetails;
import generiek.pdf.CustomAgreementData;
import generiek.pdf.CustomAgreementPdfService;
import generiek.repository.EnrollmentRepository;
import generiek.repository.CustomAgreementDetailsRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.LocalDate;
import java.util.Map;
import java.util.Optional;

@RestController
@Tag(name = "Leerovereenkomst", description = "Endpoint for generating the learning agreement PDF")
public class CustomAgreementController {

    private static final Log LOG = LogFactory.getLog(CustomAgreementController.class);

    private final CustomAgreementPdfService customAgreementPdfService;
    private final EnrollmentEndpoint enrollmentEndpoint;
    private final EnrollmentRepository enrollmentRepository;
    private final CustomAgreementDetailsRepository customAgreementDetailsRepository;

    public CustomAgreementController(CustomAgreementPdfService customAgreementPdfService,
                                      EnrollmentEndpoint enrollmentEndpoint,
                                      EnrollmentRepository enrollmentRepository,
                                      CustomAgreementDetailsRepository customAgreementDetailsRepository) {
        this.customAgreementPdfService = customAgreementPdfService;
        this.enrollmentEndpoint = enrollmentEndpoint;
        this.enrollmentRepository = enrollmentRepository;
        this.customAgreementDetailsRepository = customAgreementDetailsRepository;
    }

    @Operation(summary = "Generate and download the learning agreement",
            description = "Renders a 'Leerovereenkomst' PDF for the given enrollment, assembled from the " +
                    "student's person data, any student-supplied details, and the module/institution data " +
                    "carried through from the broker.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "PDF generated successfully",
                    content = @Content(mediaType = MediaType.APPLICATION_PDF_VALUE)),
            @ApiResponse(responseCode = "409", description = "No enrollment found for the given correlation id")
    })
    @CrossOrigin(origins = "${client.url}")
    @GetMapping(value = "/api/leerovereenkomst", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> customAgreement(
            @Parameter(description = "The correlation id of the enrollment this agreement belongs to")
            @RequestParam("correlationID") String correlationId) throws IOException {
        EnrollmentRequest enrollmentRequest = enrollmentRepository.findByIdentifier(correlationId)
                .orElseThrow(ExpiredEnrollmentRequestException::new);

        LOG.debug("Received request to generate customAgreement for correlation-id " + correlationId);

        CustomAgreementData data = assembleData(enrollmentRequest);

        byte[] pdf = customAgreementPdfService.generate(data);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.setContentDispositionFormData("attachment",
                String.format("leerovereenkomst-%s.pdf", correlationId));
        return ResponseEntity.ok().headers(headers).body(pdf);
    }

    private CustomAgreementData assembleData(EnrollmentRequest enrollmentRequest) {
        Map<String, Map<String, Object>> resolvedFields = enrollmentEndpoint.resolveStudentDetailFields(enrollmentRequest);
        Optional<CustomAgreementDetails> details = customAgreementDetailsRepository.findByEnrollmentRequest(enrollmentRequest);

        return CustomAgreementData.builder()
                .referentienummer(enrollmentRequest.getIdentifier())
                .documentDatum(LocalDate.now())
                .studentNaam(resolvedValue(resolvedFields, "naam"))
                .studentAdres(resolvedValue(resolvedFields, "adres"))
                .studentEmail(resolvedValue(resolvedFields, "email"))
                .studentTelefoon(resolvedValue(resolvedFields, "telefoon"))
                .opleiding(resolvedValue(resolvedFields, "opleiding"))
                .studentnummer(resolvedValue(resolvedFields, "studentnummer"))
                .moduleNaam(details.map(CustomAgreementDetails::getModuleNaam).orElse(null))
                .moduleCode(details.map(CustomAgreementDetails::getModuleCode).orElse(null))
                .onderwijsperiodeStart(details.map(CustomAgreementDetails::getOnderwijsperiodeStart).orElse(null))
                .onderwijsperiodeEind(details.map(CustomAgreementDetails::getOnderwijsperiodeEind).orElse(null))
                .thuisinstellingNaam(details.map(CustomAgreementDetails::getThuisinstellingNaam).orElse(null))
                .gastinstellingNaam(details.map(CustomAgreementDetails::getGastinstellingNaam).orElse(null))
                .build();
    }

    @SuppressWarnings("unchecked")
    private String resolvedValue(Map<String, Map<String, Object>> resolvedFields, String field) {
        Map<String, Object> status = resolvedFields.get(field);
        return status == null ? null : (String) status.get("value");
    }

}
