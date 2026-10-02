package generiek.pdf;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;

import java.awt.Color;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Thin layout helper around PDFBox's low-level content stream API: keeps track of the current
 * page/cursor, wraps text to a column width and breaks to a new page when content no longer fits.
 * Not thread-safe; one instance is used per generated document.
 */
class PdfLayoutContext implements AutoCloseable {

    static final float MARGIN = 50f;
    static final float PAGE_WIDTH = PDRectangle.A4.getWidth();
    static final float PAGE_HEIGHT = PDRectangle.A4.getHeight();
    static final float CONTENT_WIDTH = PAGE_WIDTH - (2 * MARGIN);
    static final float FOOTER_RESERVED_HEIGHT = 40f;
    static final float LABEL_COL_WIDTH = 150f;
    static final float SUB_LABEL_COL_WIDTH = 170f;

    static final PDFont FONT = PDType1Font.HELVETICA;
    static final PDFont FONT_BOLD = PDType1Font.HELVETICA_BOLD;
    static final PDFont FONT_ITALIC = PDType1Font.HELVETICA_OBLIQUE;

    static final Color RULE_COLOR = new Color(200, 200, 200);
    static final Color MUTED_COLOR = new Color(100, 100, 100);
    static final Color TEXT_COLOR = Color.BLACK;

    private final PDDocument document;
    private final List<PDPage> pages = new ArrayList<>();
    private PDPageContentStream stream;
    private float cursorY;

    PdfLayoutContext(PDDocument document) throws IOException {
        this.document = document;
        newPage();
    }

    void newPage() throws IOException {
        if (stream != null) {
            stream.close();
        }
        PDPage page = new PDPage(PDRectangle.A4);
        document.addPage(page);
        pages.add(page);
        stream = new PDPageContentStream(document, page);
        cursorY = PAGE_HEIGHT - MARGIN;
    }

    /**
     * Breaks to a new page if the next {@code height} points would run into the footer area.
     */
    void ensureSpace(float height) throws IOException {
        if (cursorY - height < MARGIN + FOOTER_RESERVED_HEIGHT) {
            newPage();
        }
    }

    float cursorY() {
        return cursorY;
    }

    void moveDown(float amount) {
        cursorY -= amount;
    }

    float textWidth(String text, PDFont font, float fontSize) throws IOException {
        return font.getStringWidth(text == null ? "" : text) / 1000f * fontSize;
    }

    List<String> wrap(String text, PDFont font, float fontSize, float maxWidth) throws IOException {
        List<String> lines = new ArrayList<>();
        if (text == null || text.isBlank()) {
            lines.add("");
            return lines;
        }
        StringBuilder current = new StringBuilder();
        for (String word : text.trim().split("\\s+")) {
            String candidate = current.length() == 0 ? word : current + " " + word;
            if (textWidth(candidate, font, fontSize) > maxWidth && current.length() > 0) {
                lines.add(current.toString());
                current = new StringBuilder(word);
            } else {
                current = new StringBuilder(candidate);
            }
        }
        if (current.length() > 0) {
            lines.add(current.toString());
        }
        return lines;
    }

    private void text(String text, float x, float y, PDFont font, float fontSize, Color color) throws IOException {
        stream.beginText();
        stream.setFont(font, fontSize);
        stream.setNonStrokingColor(color);
        stream.newLineAtOffset(x, y);
        stream.showText(text == null ? "" : text);
        stream.endText();
    }

    /**
     * Draws a single line at the left margin and advances the cursor.
     */
    void line(String text, PDFont font, float fontSize, Color color, float lineHeight) throws IOException {
        ensureSpace(lineHeight);
        text(text, MARGIN, cursorY, font, fontSize, color);
        moveDown(lineHeight);
    }

    void horizontalRule() throws IOException {
        ensureSpace(20f);
        moveDown(6f);
        stream.setStrokingColor(RULE_COLOR);
        stream.setLineWidth(0.75f);
        stream.moveTo(MARGIN, cursorY);
        stream.lineTo(PAGE_WIDTH - MARGIN, cursorY);
        stream.stroke();
        moveDown(14f);
    }

    /**
     * A bold "Label :" in the left column with a wrapped value starting in the second column,
     * e.g. "Thuisinstelling :" / "Gastinstelling :".
     */
    void twoColumnRow(String label, List<String> valueLines, float lineHeight) throws IOException {
        float valueX = MARGIN + LABEL_COL_WIDTH;
        float valueWidth = CONTENT_WIDTH - LABEL_COL_WIDTH;
        boolean first = true;
        if (valueLines.isEmpty()) {
            valueLines = List.of("");
        }
        for (String rawLine : valueLines) {
            for (String wrapped : wrap(rawLine, FONT, 10f, valueWidth)) {
                ensureSpace(lineHeight);
                if (first) {
                    text(label, MARGIN, cursorY, FONT_BOLD, 10.5f, TEXT_COLOR);
                }
                text(wrapped, valueX, cursorY, FONT, 10f, TEXT_COLOR);
                moveDown(lineHeight);
                first = false;
            }
        }
        moveDown(6f);
    }

    /**
     * A bold group label in the left column ("Student :"), followed by rows of sub-label/value
     * pairs in the remaining two columns.
     */
    void fieldGroup(String groupLabel, List<String[]> fields, float lineHeight) throws IOException {
        float subLabelX = MARGIN + LABEL_COL_WIDTH;
        float valueX = subLabelX + SUB_LABEL_COL_WIDTH;
        float valueWidth = CONTENT_WIDTH - LABEL_COL_WIDTH - SUB_LABEL_COL_WIDTH;
        boolean first = true;
        for (String[] field : fields) {
            String subLabel = field[0];
            String value = field.length > 1 ? field[1] : "";
            List<String> wrapped = wrap(value, FONT, 10f, valueWidth);
            boolean firstLineOfField = true;
            for (String valueLine : wrapped) {
                ensureSpace(lineHeight);
                if (first) {
                    text(groupLabel, MARGIN, cursorY, FONT_BOLD, 10.5f, TEXT_COLOR);
                }
                if (firstLineOfField) {
                    text(subLabel, subLabelX, cursorY, FONT, 10f, MUTED_COLOR);
                }
                text(valueLine, valueX, cursorY, FONT, 10f, TEXT_COLOR);
                moveDown(lineHeight);
                first = false;
                firstLineOfField = false;
            }
        }
        moveDown(6f);
    }

    void sectionHeading(String text) throws IOException {
        ensureSpace(30f);
        moveDown(8f);
        this.text(text, MARGIN, cursorY, FONT_BOLD, 14f, TEXT_COLOR);
        moveDown(20f);
    }

    void paragraph(String text, float fontSize, float lineHeight) throws IOException {
        for (String wrapped : wrap(text, FONT, fontSize, CONTENT_WIDTH)) {
            line(wrapped, FONT, fontSize, TEXT_COLOR, lineHeight);
        }
    }

    void bullet(String text, float fontSize, float lineHeight) throws IOException {
        float bulletIndent = 12f;
        float maxWidth = CONTENT_WIDTH - bulletIndent;
        boolean first = true;
        for (String wrapped : wrap(text, FONT, fontSize, maxWidth)) {
            ensureSpace(lineHeight);
            String prefix = first ? "• " : "  ";
            this.text(prefix + wrapped, MARGIN, cursorY, FONT, fontSize, TEXT_COLOR);
            moveDown(lineHeight);
            first = false;
        }
    }

    /**
     * Closes the in-progress content stream and stamps a footer (with a running page number) on
     * every page now that the total page count is known.
     */
    void finish(String referentienummer) throws IOException {
        if (stream != null) {
            stream.close();
            stream = null;
        }
        int total = pages.size();
        for (int i = 0; i < total; i++) {
            PDPage page = pages.get(i);
            try (PDPageContentStream footerStream = new PDPageContentStream(
                    document, page, PDPageContentStream.AppendMode.APPEND, true, true)) {

                String pageIndicator = (i + 1) + "/" + total;
                float pageIndicatorWidth = textWidth(pageIndicator, FONT, 9f);
                footerStream.beginText();
                footerStream.setFont(FONT, 9f);
                footerStream.setNonStrokingColor(MUTED_COLOR);
                footerStream.newLineAtOffset(PAGE_WIDTH - MARGIN - pageIndicatorWidth, PAGE_HEIGHT - 30f);
                footerStream.showText(pageIndicator);
                footerStream.endText();

                float footerY = MARGIN - 10f;
                footerStream.setStrokingColor(RULE_COLOR);
                footerStream.setLineWidth(0.75f);
                footerStream.moveTo(MARGIN, footerY + 14f);
                footerStream.lineTo(PAGE_WIDTH - MARGIN, footerY + 14f);
                footerStream.stroke();

                String footerLeft = "Leerovereenkomst - Kies op maat";
                footerStream.beginText();
                footerStream.setFont(FONT, 8f);
                footerStream.setNonStrokingColor(MUTED_COLOR);
                footerStream.newLineAtOffset(MARGIN, footerY);
                footerStream.showText(footerLeft);
                footerStream.endText();

                String footerRight = "Referentienummer : " + referentienummer;
                float footerRightWidth = textWidth(footerRight, FONT, 8f);
                footerStream.beginText();
                footerStream.setFont(FONT, 8f);
                footerStream.setNonStrokingColor(MUTED_COLOR);
                footerStream.newLineAtOffset(PAGE_WIDTH - MARGIN - footerRightWidth, footerY);
                footerStream.showText(footerRight);
                footerStream.endText();
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (stream != null) {
            stream.close();
            stream = null;
        }
    }

}
