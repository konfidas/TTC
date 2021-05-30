package de.konfidas.ttc.messages.systemlogs;

import org.apache.commons.io.FileUtils;
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

import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
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

        logger.debug("checking for SystemLogs in " + systemLogFiles.getName());
        if (!systemLogFiles.isDirectory()) {
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
        logger.debug("");
        logger.debug("============================================================================");
        logger.debug("parsing unblockUserMessage {}:", file.getName());

        byte[] content =  FileUtils.readFileToByteArray(file);

        UnblockUserSystemLogMessage message = new UnblockUserSystemLogMessage(content, file.getName());

    }
}