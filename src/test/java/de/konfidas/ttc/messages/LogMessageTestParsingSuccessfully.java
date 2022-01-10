package de.konfidas.ttc.messages;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import java.util.stream.Stream;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.Security;

public class LogMessageTestParsingSuccessfully {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    final static File correctLogs = new File("./testData/logMessages"); // TODO: as soon as we have publish-able test data, point path to it.

    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }



    @ParameterizedTest(name = "LogMessageTestParsingSuccessfully. Rest {index} => file={0}")
    @MethodSource("filesToTest")
    public void parse(File file) throws IOException, BadFormatForLogMessageException {
        logger.debug("");
        logger.debug("============================================================================");
        logger.debug("parsing log message {}:", file.getName());

        LogMessageFactory.createLogMessage(file);

    }

    public static Stream<Arguments> filesToTest(){
        return Stream.of(
                Arguments.of(new File("testdata/logMessages/Unixt_1607348284_Sig-2_Log-Aud.log")),
                Arguments.of(new File("testdata/logMessages/Unixt_1607363188_Sig-11_Log-Sys_unblockUser.log")),
                Arguments.of(new File("testdata/logMessages/Unixt_1607363188_Sig-13_Log-Sys_setConfiguration.log")));
    }
}
