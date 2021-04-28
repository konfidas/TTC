package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
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

@RunWith(Parameterized.class)
public class LogMessageTestParsingSuccessfully {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    final static File correctLogs = new File("D:\\testdata\\logMessages"); // TODO: as soon as we have publish-able test data, point path to it.

    final File file;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Parameterized.Parameters
    public static Collection<File> filesToTest(){

        logger.info("checking for Logs in "+correctLogs.getName());
        if(!correctLogs.isDirectory() || correctLogs.listFiles() == null){
            logger.error("not a directory.");
            return Collections.EMPTY_LIST;
        }

        return Arrays.asList(correctLogs.listFiles());
    }


    public LogMessageTestParsingSuccessfully(File file){
        this.file = file;
    }

    @Test
    public void parse() throws IOException, BadFormatForLogMessageException {
        logger.info("");
        logger.info("============================================================================");
        logger.info("parsing log message {}:", file.getName());

        LogMessageFactory.createLogMessage(this.file);

    }
}
