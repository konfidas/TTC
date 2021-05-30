package de.konfidas.ttc.reporting;

import de.konfidas.ttc.exceptions.LogMessageValidationException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.tars.LogMessageArchive;
import de.konfidas.ttc.validation.ValidationResult;
import de.konfidas.ttc.validation.Validator;

import java.io.*;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;

public class TextReporter implements Reporter<String> {
    File file;
    boolean skipLegitLogMessages;
    HashSet<Class<? extends ValidationException>> issuesToIgnore;

    public TextReporter(){
        this.issuesToIgnore = new HashSet<>();
        skipLegitLogMessages = false;
    }

    TextReporter skipLegitLogMessages(){
        skipLegitLogMessages = true;
        return this;
    }

    TextReporter skipLegitLogMessages(boolean skipLegitLogMessages){
        this.skipLegitLogMessages = skipLegitLogMessages;
        return this;
    }

    TextReporter ignoreIssue(Class<? extends ValidationException> t){
        issuesToIgnore.add(t);
        return this;
    }

    TextReporter ignoreIssues(Collection<Class<? extends ValidationException>> c){
        issuesToIgnore.addAll(c);
        return this;
    }

    @Override
    public String createReport(Collection<LogMessageArchive> logs, ValidationResult vResult, Boolean skipLegitLogMessages) throws ReporterException {
        this.skipLegitLogMessages = skipLegitLogMessages;
        try(StringWriter sw = new StringWriter();){

            printTars(sw, logs);
            printValidators(sw,vResult.getValidators());

            printErrorNum(sw, vResult.getValidationErrors());

            printNonLogMessageValidationExceptions(sw, vResult.getValidationErrors());

            printLogMessageDetails(sw, logs, vResult);

            return sw.toString();
        } catch (IOException e) {
            throw new ReporterException("Fehler bei der Erstellung des Reports",e);
        }

    }

    void printNonLogMessageValidationExceptions(StringWriter sw, Collection<ValidationException> validationErrors) throws IOException {
        sw.write("The following Issues, where found, but are not directly linked to Log Messages:");
        sw.write(System.lineSeparator());
        for(ValidationException v : validationErrors){
            if(!(v instanceof LogMessageValidationException)){

                if(!issuesToIgnore.contains(v.getClass())) {
                    sw.write("    "+ v.toString());
                }
            }
        }

    }

    void printLogMessageDetails(StringWriter sw, Collection<LogMessageArchive> logs, ValidationResult vResult) throws IOException {
        HashMap<LogMessage, LinkedList<LogMessageValidationException>> map = new HashMap<>();
        for(ValidationException e: vResult.getValidationErrors()){
            if(e instanceof LogMessageValidationException){
                if(!issuesToIgnore.contains(e.getClass())) {
                    if (map.containsKey(((LogMessageValidationException) e).getLogMessage())) {
                        map.get(((LogMessageValidationException) e).getLogMessage()).add((LogMessageValidationException) e);
                    } else {
                        LinkedList<LogMessageValidationException> l = new LinkedList<>();
                        l.add((LogMessageValidationException) e);
                        map.put(((LogMessageValidationException) e).getLogMessage(), l);
                    }
                }
            }
        }
        sw.write("The following errors have been found for specific log messages:");
        sw.write(System.lineSeparator());

        if(skipLegitLogMessages){
            sw.write("(legit log messages were skipped in this report)");
            sw.write(System.lineSeparator());
        }

        for(LogMessageArchive tar : logs){
            for (LogMessage lm : tar.getSortedLogMessages()){
                if(!map.containsKey(lm)){
                    if(!skipLegitLogMessages) {
                        sw.write("    " + lm.getFileName() + " seems legit.");
                        sw.write(System.lineSeparator());
                    }
                }
                    else{
                    sw.write("    "+lm.getFileName()+":");
                    sw.write(System.lineSeparator());
                    for(LogMessageValidationException e : map.get(lm)) {
                        sw.write("        " + e.toString());
                        sw.write(System.lineSeparator());
                    }
                }

            }
        }
    }

    void printErrorNum(StringWriter sw, Collection<ValidationException> validationErrors) throws IOException {
        sw.write("While validating, "+validationErrors.size()+" errors were found.");
        sw.write(System.lineSeparator());
    }

    void printTars(StringWriter sw, Collection<LogMessageArchive> logs) throws IOException {
        sw.write("This report covers the following LogMessage Archives:");
        sw.write(System.lineSeparator());

        for(LogMessageArchive l: logs){
            sw.write("    "+l.getFileName());
            sw.write(System.lineSeparator());
        }

    }


    void printValidators(StringWriter sw, Collection<Validator> validators) throws IOException {
        sw.write("To generate this report, the following validators were used:");
        sw.write(System.lineSeparator());

        for(Validator v: validators){
            sw.write("    "+v.getClass());
            sw.write(System.lineSeparator());
        }
    }


}
