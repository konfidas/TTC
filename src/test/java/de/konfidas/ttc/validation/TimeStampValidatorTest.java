package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.tars.LogMessageArchiveImplementation;
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
import java.util.Collection;
import java.util.LinkedList;
import java.util.stream.Stream;

import static org.junit.Assert.fail;

public class TimeStampValidatorTest {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);


    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    public static Stream<Arguments> filesToTest(){
        return Stream.of(
                //FIXME: Add the rest of the files here to test
                Arguments.of(new File("testdata/positive/positive_bdr_tse_web.tar"),0));
    }

    @ParameterizedTest()
    @MethodSource("filesToTest")
    public void parse(File file, int expectedNumberOfErrors) {
        logger.debug("");
        logger.debug("============================================================================");
        logger.debug("testing tar file {}:", file.getName());

        try {
            TimeStampValidator validator = new TimeStampValidator();

            LogMessageArchiveImplementation tar = new LogMessageArchiveImplementation(this.file);

            Collection<ValidationException>  errors = validator.validate(tar).getValidationErrors();

            assert(errors.size() == expectedNumberOfErrors);

        } catch (IOException | BadFormatForTARException e) {
            fail();
        }
    }
}
