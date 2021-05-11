package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.tars.LogMessageArchive;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;

public class AggregatedValidator implements Validator{
    final Collection<Validator> validators;

    public AggregatedValidator(){
        this.validators = new LinkedList<>();
    }

    public AggregatedValidator add(Validator v){

        if(v instanceof  AggregatedValidator){
            this.validators.addAll(((AggregatedValidator) v).validators);
        }else {
            this.validators.add(v);
        }

        return this;
    }

    public AggregatedValidator(Collection<Validator> validators){
        this();
        for( Validator v : validators){
            this.add(v);
        }
    }

    @Override
    public Collection<ValidationException> validate(LogMessageArchive tar) {
        ArrayList<ValidationException> result = new ArrayList<>();

        for(Validator v : validators){
            result.addAll(v.validate(tar));
        }

        return result;
    }
}
