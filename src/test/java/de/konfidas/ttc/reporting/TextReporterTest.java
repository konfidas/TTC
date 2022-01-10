package de.konfidas.ttc.reporting;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.tars.LogMessageArchiveImplementation;
import de.konfidas.ttc.validation.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import java.util.stream.Stream;

import java.io.File;
import java.io.IOException;
import java.security.Security;

import java.util.Collections;


public class TextReporterTest {

    final static File correctTarFiles = new File("testdata/positive/");


    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest(name = "TextReporterTest. Rest {index} => file={0}")
    @MethodSource("filesToTest")
    public void createReport(File file) throws IOException, BadFormatForTARException, Reporter.ReporterException {
        LogMessageArchiveImplementation tar  = new LogMessageArchiveImplementation(file);


        Validator v = new AggregatedValidator()
                .add(new CertificateFileNameValidator())
                .add(new LogMessageSignatureValidator())
                .add(new SignatureCounterValidator());

        ValidationResult result = v.validate(tar);

        TextReporter reporter = new TextReporter().skipLegitLogMessages();


        // enable the following line ot make the reporter ignore this Exception class, i.e. not reporting it:
        // reporter.ignoreIssue(SignatureCounterValidator.SignatureCounterMissingException.class);

        System.out.println(reporter.createReport(Collections.singleton(tar), result, false));
    }

    public static Stream<Arguments> filesToTest(){
        return Stream.of(
                //FIXME: Add the rest of the files here to test
                Arguments.of(new File("testdata/positive/4b5ba740-06fe-4506-9afc-e9f1eabadaa4.tar")));
    }

}
