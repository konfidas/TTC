package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.BadFormatForTARException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.validation.AggregatedValidator;
import de.konfidas.ttc.validation.CertificateFileNameValidator;
import de.konfidas.ttc.validation.LogMessageSignatureValidator;
import de.konfidas.ttc.validation.Validator;
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

import static org.junit.jupiter.api.Assertions.assertTrue;


public class LogMessageArchiveTestParsingSuccessfully {
    final static Logger logger = LoggerFactory.getLogger(LogMessageArchiveTestParsingSuccessfully.class);
    final static File correctTarFiles = new File("testdata/positive/");


    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }


    public static Stream<Arguments> filesToTest(){
        return Stream.of(
                //FIXME: Add the rest of the files here to test
                Arguments.of(new File("testdata/positive/4b5ba740-06fe-4506-9afc-e9f1eabadaa4.tar")));
    }

    @ParameterizedTest(name = "LogMessageArchiveTestParsingSuccessfully. Rest {index} => file={0}")
    @MethodSource("filesToTest")
    public void parse(File file) throws IOException, BadFormatForTARException {
        logger.debug("");
        logger.debug("============================================================================");
        logger.debug("testing tar file {}:", file.getName());

        LogMessageArchiveImplementation tar  = new LogMessageArchiveImplementation(file);


        Validator v = new AggregatedValidator()
                .add(new CertificateFileNameValidator())
                .add(new LogMessageSignatureValidator());

        Collection<ValidationException> errors = v.validate(tar).getValidationErrors();
        assertTrue(errors.isEmpty());
    }
}
