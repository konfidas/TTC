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

@RunWith(Parameterized.class)
public class LogMessageTestParsingSuccessfully {
    final static Logger logger = LoggerFactory.getLogger(LogMessageArchiveTestParsingSuccessfully.class);
    final static File correctTarFiles = new File("D:\\testdata\\LogMessages"); // TODO: as soon as we have publish-able test data, point path to it.

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


    public LogMessageTestParsingSuccessfully(File file){
        this.file = file;
    }

    @Test
    public void parse() throws IOException, BadFormatForLogMessageException {
        logger.info("");
        logger.info("============================================================================");
        logger.info("parsing log message {}:", file.getName());

        LogMessage msg  = LogMessageFactory.createLogMessage(this.file);

    }
}
