package de.konfidas.ttc.validation;

import de.konfidas.ttc.tars.LogMessageArchive;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;

public class AggregatedValidator implements Validator{
    Collection<Validator> validators;

    public AggregatedValidator(){
        this.validators = new LinkedList<>();
    }

    public AggregatedValidator add(Validator v){
        this.validators.add(v);
        return this;
    }

    public AggregatedValidator(Collection<Validator> validators){
        this.validators = validators;
    }

    @Override
    public Collection<ValidationException> validate(LogMessageArchive tar) {
        ArrayList<ValidationException> result = new ArrayList<ValidationException>();

        for(Validator v : validators){
            result.addAll(v.validate(tar));
        }

        return result;
    }
}
