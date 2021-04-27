package de.konfidas.ttc.messages.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.messages.systemlogs.UnblockUserSystemLogMessage;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
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

public class TestUnblockUser {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    final static File systemLogFiles = new File("testdata/systemlogs/unblockuser/");

    File file;

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Parameterized.Parameters
    public static Collection filesToTest() {

        logger.info("checking for SystemLogs in " + systemLogFiles.getName());
        if (null == systemLogFiles || !systemLogFiles.isDirectory()) {
            fail("not a directory.");

            return Collections.EMPTY_LIST;
        }

        return Arrays.asList(systemLogFiles.listFiles());
    }

    public TestUnblockUser(File file) {
        this.file = file;
    }

    @Test
    public void parse() throws Exception {
        logger.info("");
        logger.info("============================================================================");
        logger.info("parsing unblockUserMessage {}:", file.getName());

        byte[] content =  FileUtils.readFileToByteArray(file);

        UnblockUserSystemLogMessage message = new UnblockUserSystemLogMessage(content, file.getName());

    }
}
