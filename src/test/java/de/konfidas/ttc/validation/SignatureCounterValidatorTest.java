package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.tars.LogMessageArchiveImplementation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.Collection;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.ParameterizedTest;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.params.provider.Arguments;
import java.util.stream.Stream;


public class SignatureCounterValidatorTest {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    @ParameterizedTest(name = "SignatureCounterValidatorTest. Rest {index} => file={0}")
    @MethodSource("parseProvider")
    public void parse(File file, int expectedNumberOfErrors) {
        logger.debug("");
        logger.debug("============================================================================");
        logger.debug("testing tar file {}:", file.getName());

        try {
            SignatureCounterValidator validator = new SignatureCounterValidator();

            LogMessageArchiveImplementation tar = new LogMessageArchiveImplementation(file);

            Collection<ValidationException>  errors = validator.validate(tar).getValidationErrors();

            assert(errors.size() == expectedNumberOfErrors);

        } catch (IOException | BadFormatForTARException e) {
            fail();
        }
    }
    private static Stream<Arguments>  parseProvider() {
        return Stream.of(
                //FIXME: Add the rest of the files here to test
                Arguments.of(new File("testdata/positive/4b5ba740-06fe-4506-9afc-e9f1eabadaa4.tar"),1));
    }
}
