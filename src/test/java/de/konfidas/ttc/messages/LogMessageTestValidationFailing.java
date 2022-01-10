package de.konfidas.ttc.messages;

import de.konfidas.ttc.tars.LogMessageArchiveImplementation;
import de.konfidas.ttc.validation.AggregatedValidator;
import de.konfidas.ttc.validation.CertificateFileNameValidator;
import de.konfidas.ttc.validation.LogMessageSignatureValidator;
import de.konfidas.ttc.validation.Validator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.Security;
import java.util.stream.Stream;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;


public class LogMessageTestValidationFailing {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    final static File brokenTarFiles = new File("testdata" + File.separator + "negative" + File.separator + "validation_errors");

    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @MethodSource("filesToTest")
    public void validateTARwithErrors_shouldShowValidationErrors(File tarFile) throws Exception {
        logger.debug("");
        logger.debug("============================================================================");
        logger.debug("testing tar file {}:", tarFile.getName());

        assertFalse(((Validator) new AggregatedValidator()
                .add(new CertificateFileNameValidator())
                .add(new LogMessageSignatureValidator())).validate(new LogMessageArchiveImplementation(tarFile)).getValidationErrors().isEmpty());
    }

    static Stream<File> filesToTest() {
        logger.debug("checking for Tars in " + brokenTarFiles.getName());
        if (!brokenTarFiles.isDirectory()) {
            fail(brokenTarFiles.getAbsolutePath() + " is not a directory.");
        }
        if (brokenTarFiles.listFiles() == null) {
            fail("The directory of test TAR files is empty in: " + brokenTarFiles.getAbsolutePath());
        }
        return Stream.of(brokenTarFiles.listFiles());
    }
}
