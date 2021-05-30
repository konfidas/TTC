package de.konfidas.ttc.reporting;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.tars.LogMessageArchiveImplementation;
import de.konfidas.ttc.validation.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class TextReporterTest {

    final static File correctTarFiles = new File("testdata/positive/");

    final File file;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Parameterized.Parameters
    public static Collection<File> filesToTest(){
        if(!correctTarFiles.isDirectory() || correctTarFiles.listFiles() == null){
            fail("not a directory.");
        }
        return Arrays.asList(correctTarFiles.listFiles());
    }


    public TextReporterTest(File file){
        this.file = file;
    }

    @Test
    public void createReport() throws IOException, BadFormatForTARException, Reporter.ReporterException {
        LogMessageArchiveImplementation tar  = new LogMessageArchiveImplementation(this.file);

//        File reportFile = new File("./Report_"+this.file.getName()+".html");


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

}
