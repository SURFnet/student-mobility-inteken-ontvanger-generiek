package generiek.pdf;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;
import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "The data required to render a 'Leerovereenkomst' (learning agreement) PDF")
public class CustomAgreementData {

    @Schema(example = "241457-369644-143491", required = true)
    private String referentienummer;

    @Schema(description = "The date the agreement document was generated", example = "2025-09-22", required = true)
    private LocalDate documentDatum;

    @Schema(example = "AHR (Ruth) Bootsma", required = true)
    private String studentNaam;

    @Schema(example = "000019", required = true)
    private String studentnummer;

    @Schema(example = "Advanced Business Creation (Bachelor)", required = true)
    private String opleiding;

    @Schema(example = "Hoofdfase")
    private String studiefase;

    @Schema(example = "ruthbootsmasurfnl@example.com", required = true)
    private String studentEmail;

    @Schema(example = "+31622881967")
    private String studentTelefoon;

    @Schema(example = "Julianastraat 38, 3911 HK Rhenen")
    private String studentAdres;

    @Schema(example = "Hogeschool Utrecht")
    private String thuisinstellingNaam;

    @Schema(example = "Hogeschool Inholland", required = true)
    private String gastinstellingNaam;

    @Schema(description = "Deadline by which the signed agreement must be received by the guest institution",
            example = "2025-11-09")
    private LocalDate gastinstellingDeadline;

    @Schema(description = "The postal address of the guest institution, one line per entry",
            example = "[\"T.a.v. CSA - KOM\", \"Postbus 558\", \"2003 RN Haarlem\"]")
    private List<String> gastinstellingAdresRegels;

    @Schema(example = "keuzeonderwijs@inholland.nl")
    private String gastinstellingEmail;

    @Schema(example = "KoM")
    private String gastinstellingEmailOnderwerp;

    @Schema(example = "Audiovisual Production (ENG) - 2025-2026", required = true)
    private String moduleNaam;

    @Schema(example = "K130901")
    private String moduleCode;

    @Schema(example = "2026-02-02")
    private LocalDate onderwijsperiodeStart;

    @Schema(example = "2026-07-03")
    private LocalDate onderwijsperiodeEind;

    @Schema(example = "Creative Business")
    private String faculteit;

    @Schema(example = "Voltijd")
    private String onderwijsvorm;

    @Schema(example = "")
    private String ingangseisen;

    @Schema(example = "Presentations, papers (research and essays) and delivery of video productions " +
            "with all the associated documentation (planning, budgets, scripts, etc).")
    private String toetsing;

    @Schema(example = "30.0", required = true)
    private double aantalEc;

}
