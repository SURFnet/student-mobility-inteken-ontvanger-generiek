package generiek.pdf;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

import static generiek.pdf.PdfLayoutContext.FONT;
import static generiek.pdf.PdfLayoutContext.FONT_BOLD;
import static generiek.pdf.PdfLayoutContext.FONT_ITALIC;
import static generiek.pdf.PdfLayoutContext.MUTED_COLOR;
import static generiek.pdf.PdfLayoutContext.TEXT_COLOR;

/**
 * Renders a "CustomAgreement" (Kies op maat style learning agreement) PDF with Apache PDFBox,
 * modelled after the reference document: title block, "De partijen", "Gegevens van de module"
 * and "De overeenkomst" sections, followed by three signature blocks.
 */
@Service
public class CustomAgreementPdfService {

    private static final DateTimeFormatter TITLE_DATE_FORMAT =
            DateTimeFormatter.ofPattern("d MMMM yyyy", new Locale("nl"));
    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("d MMMM yyyy", new Locale("nl"));
    private static final DateTimeFormatter SUMMARY_DATE_FORMAT =
            DateTimeFormatter.ofPattern("dd-MM-yyyy", new Locale("nl"));

    private static final List<String> OVEREENKOMST_BEPALINGEN = List.of(
            "Bovengenoemde instellingen zijn overeengekomen dat genoemde student bevoegd is en toegelaten " +
                    "wordt om de module te volgen bij de gastinstelling, met inachtneming van alle in de " +
                    "procedures beschreven afspraken rond informatie-uitwisseling en van het elders gevolgde " +
                    "onderwijs.",
            "Student en thuisinstelling verwachten dat de student bij de start van de module voldoet aan de " +
                    "toelatingseisen. Indien dat niet het geval is, kan de gastinstelling alsnog de student " +
                    "afwijzen voor deelname aan de module.",
            "De student is akkoord dat de gegevens die noodzakelijk zijn voor het realiseren van de " +
                    "uitwisseling beschikbaar gesteld worden aan alle betrokken partijen bij deze uitwisseling.",
            "De thuisinstelling verklaart dat bij succesvol afronden van de module de behaalde EC's worden " +
                    "erkend door de thuisinstelling.",
            "Het is de verantwoordelijkheid van de student om de behaalde resultaten bij de gastinstelling " +
                    "over te laten zetten bij de thuisinstelling."
    );

    public byte[] generate(CustomAgreementData data) throws IOException {
        try (PDDocument document = new PDDocument();
             PdfLayoutContext layout = new PdfLayoutContext(document)) {

            writeHeader(layout, data);
            writeDePartijen(layout, data);
            writeGegevensVanDeModule(layout, data);
            writeDeOvereenkomst(layout, data);

            layout.finish(data.getReferentienummer());

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }

    private void writeHeader(PdfLayoutContext layout, CustomAgreementData data) throws IOException {
        layout.line("Leerovereenkomst", FONT_BOLD, 22f, TEXT_COLOR, 30f);
        LocalDate documentDatum = data.getDocumentDatum() != null ? data.getDocumentDatum() : LocalDate.now();
        layout.line(TITLE_DATE_FORMAT.format(documentDatum).toUpperCase(new Locale("nl")), FONT, 11f, MUTED_COLOR, 22f);
        layout.line("Referentienummer : " + data.getReferentienummer(), FONT, 10f, TEXT_COLOR, 16f);
        layout.horizontalRule();
    }

    private void writeDePartijen(PdfLayoutContext layout, CustomAgreementData data) throws IOException {
        layout.sectionHeading("De partijen");

        layout.fieldGroup("Student :", List.of(
                new String[]{"Naam", nullToEmpty(data.getStudentNaam())},
                new String[]{"Studentnummer bij eigen instelling", nullToEmpty(data.getStudentnummer())},
                new String[]{"Opleiding", nullToEmpty(data.getOpleiding())},
                new String[]{"Studiefase", nullToEmpty(data.getStudiefase())},
                new String[]{"E-mail", nullToEmpty(data.getStudentEmail())},
                new String[]{"Telefoon", nullToEmpty(data.getStudentTelefoon())}
        ), 15f);
        layout.horizontalRule();

        layout.twoColumnRow("Thuisinstelling :", List.of(nullToEmpty(data.getThuisinstellingNaam())), 15f);
        layout.horizontalRule();

        layout.twoColumnRow("Gastinstelling :", gastinstellingLines(data), 15f);
        layout.horizontalRule();
    }

    private List<String> gastinstellingLines(CustomAgreementData data) {
        List<String> lines = new java.util.ArrayList<>();
        lines.add(nullToEmpty(data.getGastinstellingNaam()));
        lines.add("");
        if (data.getGastinstellingDeadline() != null) {
            lines.add(String.format(
                    "Zorg dat alle pagina's van de ondertekende leerovereenkomst uiterlijk %s ontvangen zijn bij :",
                    DATE_FORMAT.format(data.getGastinstellingDeadline())));
        }
        lines.add(nullToEmpty(data.getGastinstellingNaam()));
        if (data.getGastinstellingAdresRegels() != null) {
            lines.addAll(data.getGastinstellingAdresRegels());
        }
        lines.add("");
        if (StringUtils.hasText(data.getGastinstellingEmail())) {
            lines.add("Bij voorkeur en voor snelle afhandeling de leerovereenkomst gescand mailen naar: "
                    + data.getGastinstellingEmail());
        }
        if (StringUtils.hasText(data.getGastinstellingEmailOnderwerp())) {
            lines.add("Vul bij onderwerp in: '" + data.getGastinstellingEmailOnderwerp() + "' en jouw eigen naam.");
        }
        return lines;
    }

    private void writeGegevensVanDeModule(PdfLayoutContext layout, CustomAgreementData data) throws IOException {
        layout.sectionHeading("Gegevens van de module");

        String onderwijsperiode = "";
        if (data.getOnderwijsperiodeStart() != null && data.getOnderwijsperiodeEind() != null) {
            onderwijsperiode = DATE_FORMAT.format(data.getOnderwijsperiodeStart()) + " - "
                    + DATE_FORMAT.format(data.getOnderwijsperiodeEind());
        }

        layout.fieldGroup("", List.of(
                new String[]{"Naam", nullToEmpty(data.getModuleNaam())},
                new String[]{"Modulecode", nullToEmpty(data.getModuleCode())},
                new String[]{"Onderwijsperiode", onderwijsperiode},
                new String[]{"Faculteit", nullToEmpty(data.getFaculteit())},
                new String[]{"Onderwijsvorm", nullToEmpty(data.getOnderwijsvorm())},
                new String[]{"Ingangseisen", nullToEmpty(data.getIngangseisen())},
                new String[]{"Toetsing", nullToEmpty(data.getToetsing())},
                new String[]{"Aantal EC", data.getAantalEc() > 0 ? String.valueOf(data.getAantalEc()) : ""}
        ), 15f);
        layout.horizontalRule();
    }

    private void writeDeOvereenkomst(PdfLayoutContext layout, CustomAgreementData data) throws IOException {
        layout.sectionHeading("De overeenkomst");

        String ec = data.getAantalEc() > 0 ? data.getAantalEc() + " EC" : "";
        String period = "";
        if (data.getOnderwijsperiodeStart() != null || data.getOnderwijsperiodeEind() != null) {
            String start = data.getOnderwijsperiodeStart() != null ? SUMMARY_DATE_FORMAT.format(data.getOnderwijsperiodeStart()) : "?";
            String eind = data.getOnderwijsperiodeEind() != null ? SUMMARY_DATE_FORMAT.format(data.getOnderwijsperiodeEind()) : "?";
            period = start + " - " + eind;
        }
        String summary = List.of(nullToEmpty(data.getReferentienummer()), nullToEmpty(data.getModuleNaam()), ec, period)
                .stream().filter(StringUtils::hasText).collect(java.util.stream.Collectors.joining(" • "));
        layout.line(summary, FONT, 9f, MUTED_COLOR, 20f);

        for (String bepaling : OVEREENKOMST_BEPALINGEN) {
            layout.bullet(bepaling, 10f, 14f);
        }
        layout.moveDown(10f);

        writeSignatureBlock(layout, "Handtekening student", "Let op: vul hieronder alle gegevens volledig in", List.of(
                new String[]{"Plaats, datum", ""},
                new String[]{"Naam", nullToEmpty(data.getStudentNaam())},
                new String[]{"Adres", nullToEmpty(data.getStudentAdres())},
                new String[]{"Handtekening", ""}
        ), "Alle regels invullen");

        writeSignatureBlock(layout, "Handtekening namens de examencommissie van "
                + nullToEmpty(data.getThuisinstellingNaam()), null, List.of(
                new String[]{"Plaats, datum", ""},
                new String[]{"Functie", ""},
                new String[]{"Naam", ""},
                new String[]{"Handtekening", ""}
        ), "Stempel instelling");

        writeSignatureBlock(layout, "Handtekening namens " + nullToEmpty(data.getGastinstellingNaam()), null, List.of(
                new String[]{"Plaats, datum", ""},
                new String[]{"Functie", ""},
                new String[]{"Naam", ""},
                new String[]{"Handtekening", ""}
        ), "Stempel instelling");
    }

    private void writeSignatureBlock(PdfLayoutContext layout, String heading, String note,
                                     List<String[]> rows, String sideNote) throws IOException {
        layout.ensureSpace(30f);
        layout.moveDown(10f);
        layout.line(heading + " :", FONT_BOLD, 11f, TEXT_COLOR, 16f);
        if (note != null) {
            layout.line(note, FONT_ITALIC, 8.5f, MUTED_COLOR, 14f);
        }
        layout.fieldGroup("", rows, 18f);
        if (StringUtils.hasText(sideNote)) {
            layout.line(sideNote, FONT_ITALIC, 8.5f, MUTED_COLOR, 14f);
        }
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

}
