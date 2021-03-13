package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
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
import java.util.Collections;

import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class LogMessageArchiveTestParsingFailing {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    final static File brokenTarFiles = new File("D:\\testdata\\brokenTars"); // TODO: as soon as we have publish-able test data, point path to it.

    File file;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Parameterized.Parameters
    public static Collection filesToTest(){

        logger.info("checking for Tars in "+brokenTarFiles.getName());
        if(null == brokenTarFiles || !brokenTarFiles.isDirectory()){
            logger.error("not a directory.");
            return Collections.EMPTY_LIST;
        }

        return Arrays.asList(brokenTarFiles.listFiles());
    }

    public LogMessageArchiveTestParsingFailing(File file){
        this.file = file;
    }

    @Test
    public void parse() throws IOException{
        logger.info("");
        logger.info("============================================================================");
        logger.info("testing tar file {}:", file.getName());

        try {
            LogMessageArchive tar = new LogMessageArchive(this.file);

            fail("Log Message parsing successful, but expected to fail");
        }catch(IOException | BadFormatForTARException e){
            // expected behaviour
        }

    }
}
