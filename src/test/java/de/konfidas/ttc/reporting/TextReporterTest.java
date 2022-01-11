package de.konfidas.ttc.reporting;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.tars.LogMessageArchiveImplementation;
import de.konfidas.ttc.validation.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.Collections;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.stream.Stream;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;


public class TextReporterTest {

    final static File correctLogs = new File("testdata" + File.separator + "positive" + File.separator + "can_parse");

    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
        ResourceBundle properties = ResourceBundle.getBundle("ttc", new Locale("de", "DE"));
    }

    @ParameterizedTest
    @MethodSource("filesToTest")
    public void createTextReport_ShouldNotBeNull(File file) throws IOException, BadFormatForTARException, Reporter.ReporterException {
        LogMessageArchiveImplementation tar = new LogMessageArchiveImplementation(file);

        Validator v = new AggregatedValidator()
                .add(new CertificateFileNameValidator())
                .add(new LogMessageSignatureValidator())
                .add(new SignatureCounterValidator());

        ValidationResult result = v.validate(tar);

        try {
            assertNotNull("Text report for " + tar.getFileName() + " is null.", new TextReporter().skipLegitLogMessages().createReport(Collections.singleton(tar), result, true));
        } catch (Exception e) {
            fail("Text report for " + tar.getFileName() + " threw Exception " + e.getMessage());
        }
    }

    static Stream<File> filesToTest() {
        if (!correctLogs.isDirectory()) {
            fail(correctLogs.getAbsolutePath() + " is not a directory.");
        }
        if (correctLogs.listFiles() == null) {
            fail("The directory of test TAR files is empty in: " + correctLogs.getAbsolutePath());
        }
        return Stream.of(correctLogs.listFiles());
    }


}
