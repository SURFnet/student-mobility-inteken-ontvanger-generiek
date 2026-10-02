package generiek.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Schema(description = "Student-supplied personal details submitted from the generiek client")
public class StudentDetailsForm {

    @Schema(example = "550e8400-e29b-41d4-a716-446655440000", required = true)
    private String correlationID;

    @Schema(example = "AHR (Ruth) Bootsma")
    private String naam;

    @Schema(example = "Julianastraat 38, 3911 HK Rhenen")
    private String adres;

    @Schema(example = "ruthbootsmasurfnl@example.com")
    private String email;

    @Schema(example = "+31622881967")
    private String telefoon;

    @Schema(example = "Advanced Business Creation (Bachelor)")
    private String opleiding;

    @Schema(example = "000019")
    private String studentnummer;

}
