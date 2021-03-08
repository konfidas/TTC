package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.tars.LogMessageArchiveTestParsingSuccessfully;
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
public class LogMessageTestParsingFailing {
    final static Logger logger = LoggerFactory.getLogger(LogMessageArchiveTestParsingSuccessfully.class);
    final static File correctTarFiles = new File("D:\\testdata\\BrokenLogMessages"); // TODO: as soon as we have publish-able test data, point path to it.

    File file;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Parameterized.Parameters
    public static Collection tarFilesToTest(){

        if(null == correctTarFiles || !correctTarFiles.isDirectory()){
            return Collections.EMPTY_LIST;
        }
        return Arrays.asList(correctTarFiles.listFiles());
    }


    public LogMessageTestParsingFailing(File file){
        this.file = file;
    }

    @Test
    public void parse() throws IOException {
        logger.info("");
        logger.info("============================================================================");
        logger.info("parsing log message {}:", file.getName());

        try {
            LogMessage msg = LogMessageFactory.createLogMessage(this.file);

            fail("Log message was parsed, but expected to fail.");
        }catch(BadFormatForLogMessageException e){
            // expected exception
        }
    }
}
