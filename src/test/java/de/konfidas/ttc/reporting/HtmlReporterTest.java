package de.konfidas.ttc.reporting;
import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.tars.LogMessageArchiveImplementation;
import de.konfidas.ttc.validation.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Security;

import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import java.util.stream.Stream;

public class HtmlReporterTest {

    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @ParameterizedTest(name = "HtmlReporterTest. Rest {index} => file={0}")
    @MethodSource("filesToTest")
    public void createReport(File file) throws IOException, BadFormatForTARException, Reporter.ReporterException {
        LogMessageArchiveImplementation tar  = new LogMessageArchiveImplementation(file);

        File reportFile = new File("./Report_"+file.getName()+".html");


        Validator v = new AggregatedValidator()
                .add(new CertificateFileNameValidator())
                .add(new LogMessageSignatureValidator())
                .add(new SignatureCounterValidator());

        ValidationResult result = v.validate(tar);

        HtmlReporter reporter = new HtmlReporter().skipLegitLogMessages();

        Files.writeString(reportFile.toPath(), reporter.createReport(Collections.singleton(tar),result,true));

    }

    public static Stream<Arguments> filesToTest(){
        return Stream.of(
                //FIXME: Add the rest of the files here to test
                Arguments.of(new File("testdata/positive/4b5ba740-06fe-4506-9afc-e9f1eabadaa4.tar")));
    }

}
