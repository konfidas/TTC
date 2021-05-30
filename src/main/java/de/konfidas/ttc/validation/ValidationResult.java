package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.ValidationException;

import java.util.Collection;

public interface ValidationResult {
    Collection<Validator> getValidators();
    Collection<ValidationException> getValidationErrors();
}
