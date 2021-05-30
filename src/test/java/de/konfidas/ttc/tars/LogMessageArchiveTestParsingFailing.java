package de.konfidas.ttc.tars;

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
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static org.junit.Assert.assertFalse;

@RunWith(Parameterized.class)
public class LogMessageArchiveTestParsingFailing {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    final static File brokenTarFiles = new File("D:\\testdata\\brokenTars"); // TODO: as soon as we have publish-able test data, point path to it.

    final File file;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Parameterized.Parameters
    public static Collection<File> filesToTest(){

        logger.debug("checking for Tars in "+brokenTarFiles.getName());
        if(!brokenTarFiles.isDirectory() ||brokenTarFiles.listFiles() == null){
            logger.error("not a directory.");
            return Collections.EMPTY_LIST;
        }

        return Arrays.asList(brokenTarFiles.listFiles());
    }

    public LogMessageArchiveTestParsingFailing(File file){
        this.file = file;
    }

    @Test
    public void parse() throws Exception{
        logger.debug("");
        logger.debug("============================================================================");
        logger.debug("testing tar file {}:", file.getName());

        LogMessageArchiveImplementation tar = new LogMessageArchiveImplementation(this.file);

        Validator v = new AggregatedValidator()
                    .add(new CertificateFileNameValidator())
                    .add(new LogMessageSignatureValidator());

        assertFalse(v.validate(tar).getValidationErrors().isEmpty());

    }
}
