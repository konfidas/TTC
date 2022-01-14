package de.konfidas.ttc.messages.systemlogs;

import org.apache.commons.io.FileUtils;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.assertTrue;

import static org.junit.jupiter.api.Assertions.fail;


public class TestUnblockUser {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    final static File systemLogFiles = new File("testdata/systemlogs/unblockuser/");


    static Stream<File> filesToTest() {
        logger.debug("checking system logs in " + systemLogFiles.getName());
        if (!systemLogFiles.isDirectory()) {
            fail(systemLogFiles.getAbsolutePath() + " is not a directory.");
        }
        if (systemLogFiles.listFiles() == null) {
            fail("The directory of system logs  is empty in: " + systemLogFiles.getAbsolutePath());
        }
        return Stream.of(systemLogFiles.listFiles());
    }


    @ParameterizedTest
    @MethodSource("filesToTest")
    public void parse(File syslog) throws Exception {

        logger.debug("");
        logger.debug("============================================================================");
        logger.debug("Parsing unblockUserMessage {}:", syslog.getName());

        byte[] content =  FileUtils.readFileToByteArray(syslog);

        UnblockUserSystemLogMessage message = new UnblockUserSystemLogMessage(content, syslog.getName());
        assertTrue( message.getAllErrors().size() ==0);

    }
}