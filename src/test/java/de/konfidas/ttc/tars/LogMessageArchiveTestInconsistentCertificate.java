
package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.Security;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.fail;


public class LogMessageArchiveTestInconsistentCertificate {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    final static File brokenTarFiles = new File("testdata/negative/inconsistent_certificates/");


    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @ParameterizedTest(name = "LogMessageArchiveTestInconsistentCertificate. Rest {index} => file={0}")
    @MethodSource("filesToTest")
    public void parse(File file ) throws IOException {
        logger.debug("");
        logger.debug("============================================================================");
        logger.debug("testing tar file {}:", file.getName());

        try {
            new LogMessageArchiveImplementation(file);
            fail("Log Message parsing successful, but expected to fail");
        }
        catch ( BadFormatForTARException e) {
            // expected behaviour
        }
    }
    public static Stream<Arguments> filesToTest(){

        logger.debug("checking for Tars in " + brokenTarFiles.getName());
        if (!brokenTarFiles.isDirectory() || brokenTarFiles.listFiles() == null) {
            return Stream.of();
        }
        return Stream.of(
                Arguments.of(brokenTarFiles.listFiles()));
    }


}
