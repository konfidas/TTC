package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.ValidationException;

import java.util.ArrayList;
import java.util.Collection;

class ValidationResultImpl implements ValidationResult{
    ArrayList<Validator> validators;
    ArrayList<ValidationException> errors;

    public ValidationResultImpl(){
        validators = new ArrayList<>();
        errors = new ArrayList<>();
    }

    public ValidationResultImpl append(Collection<Validator> validators, Collection<ValidationException> errors){
        this.validators.addAll(validators);
        this.errors.addAll(errors);
        return this;
    }

    public ValidationResultImpl append(ValidationResult v){
        this.validators.addAll(v.getValidators());
        this.errors.addAll(v.getValidationErrors());
        return this;
    }

    @Override
    public Collection<Validator> getValidators() {
        return validators;
    }

    @Override
    public Collection<ValidationException> getValidationErrors() {
        return errors;
    }
}
