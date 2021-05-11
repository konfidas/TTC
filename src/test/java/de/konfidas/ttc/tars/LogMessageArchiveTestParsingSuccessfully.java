package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.LogMessagePrinter;
import de.konfidas.ttc.validation.*;
import de.konfidas.ttc.reporting.LogMessageReporter;
import de.konfidas.ttc.reporting.ReportTextPrinter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class LogMessageArchiveTestParsingSuccessfully {
    final static Logger logger = LoggerFactory.getLogger(LogMessageArchiveTestParsingSuccessfully.class);
    final static File correctTarFiles = new File("testdata/positive/");

    final File file;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Parameterized.Parameters
    public static Collection<File> filesToTest(){

        logger.info("checking for Tars in "+correctTarFiles.getName());
        if(!correctTarFiles.isDirectory() || correctTarFiles.listFiles() == null){
            fail("not a directory.");
        }
        return Arrays.asList(correctTarFiles.listFiles());
    }


    public LogMessageArchiveTestParsingSuccessfully(File file){
        this.file = file;
    }

    @Test
    public void parse() throws IOException, BadFormatForTARException {
        logger.info("");
        logger.info("============================================================================");
        logger.info("testing tar file {}:", file.getName());

        LogMessageArchiveImplementation tar  = new LogMessageArchiveImplementation(this.file);
        for (LogMessage message : tar.getLogMessages()) {
            LogMessageReporter testReporter = new LogMessageReporter(message);
            logger.info( ReportTextPrinter.printReportToText(testReporter,0));
        }
        Validator v = new AggregatedValidator()
                .add(new CertificateFileNameValidator())
                .add(new LogMessageSignatureValidator())
                .add(new LogMessageFileNameValidator())
                .add(new SignatureCounterValidator())
                .add(new TimeStampValidator())
                .add(new TransactionCounterValidator());

        Collection<ValidationException> errors = v.validate(tar);
        assertTrue(errors.size() == 1);
    }
}
