package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.tars.LogMessageArchiveImplementation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.security.Security;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;


public class SignatureCounterValidatorTest {

    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @Disabled
    public void validateSignatureCounter_ShouldFind3Errors() {

        try {
            LogMessageArchiveImplementation tar = new LogMessageArchiveImplementation(new File("testdata" + File.separator + "negative" + File.separator + "signature_validation_errors" + File.separator + "6e6c6a42-5c8d-4a9c-9572-26c10619d020.tar"));
            Collection<ValidationException> errors = new SignatureCounterValidator().validate(tar).getValidationErrors();
            assertEquals(3, errors.size());

        } catch (Exception e) {
            fail("An Exception was thrown but should not have been: " + e.getMessage());
        }
    }
}
