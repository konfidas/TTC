package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.LogMessagePrinter;
import de.konfidas.ttc.validation.AggregatedValidator;
import de.konfidas.ttc.validation.CertificateFileNameValidator;
import de.konfidas.ttc.validation.LogMessageSignatureValidator;
import de.konfidas.ttc.validation.Validator;
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

    File file;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Parameterized.Parameters
    public static Collection filesToTest(){

        logger.info("checking for Tars in "+correctTarFiles.getName());
        if(null == correctTarFiles || !correctTarFiles.isDirectory()){
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

        LogMessageArchive tar  = new LogMessageArchive(this.file);
        for (LogMessage message : tar.getAll_log_messages()) {
            logger.info(LogMessagePrinter.printMessage(message));
            int a =0;
        }
        Validator v = new AggregatedValidator()
                .add(new CertificateFileNameValidator())
                .add(new LogMessageSignatureValidator());

        Collection<ValidationException> errors = v.validate(tar);
        assertTrue(errors.isEmpty());
    }
}
