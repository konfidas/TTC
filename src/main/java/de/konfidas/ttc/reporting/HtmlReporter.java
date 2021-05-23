package de.konfidas.ttc.reporting;

import de.konfidas.ttc.exceptions.LogMessageValidationException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.tars.LogMessageArchive;
import de.konfidas.ttc.validation.ValidationResult;
import de.konfidas.ttc.validation.Validator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;

public class HtmlReporter implements Reporter<File> {
    File file;
    boolean skipLegitLogMessages;
    HashSet<Class<? extends ValidationException>> issuesToIgnore;

    public HtmlReporter(File file){
        this.file= file;
        this.issuesToIgnore = new HashSet<>();
        skipLegitLogMessages = false;
    }

    HtmlReporter skipLegitLogMessages(){
        skipLegitLogMessages = true;
        return this;
    }

    HtmlReporter skipLegitLogMessages(boolean skipLegitLogMessages){
        this.skipLegitLogMessages = skipLegitLogMessages;
        return this;
    }

    HtmlReporter ignoreIssue(Class<? extends ValidationException> t){
        issuesToIgnore.add(t);
        return this;
    }

    HtmlReporter ignoreIssues(Collection<Class<? extends ValidationException>> c){
        issuesToIgnore.addAll(c);
        return this;
    }

    @Override
    public File createReport(Collection<LogMessageArchive> logs, ValidationResult vResult) throws ReporterException {
        try(BufferedWriter bw = new BufferedWriter(new FileWriter(file));){
            printHeader(bw);

            printTars(bw, logs);
            printValidators(bw,vResult.getValidators());

            printErrorNum(bw, vResult.getValidationErrors());

            printNonLogMessageValidationExceptions(bw, vResult.getValidationErrors());

            printLogMessageDetails(bw, logs, vResult);

            printFooter(bw);
            bw.flush();
            return file;
        } catch (IOException e) {
            throw new ReporterException("Fehler bei der Erstellung des HTML Reports",e);
        }

    }

    void printNonLogMessageValidationExceptions(BufferedWriter bw, Collection<ValidationException> validationErrors) throws IOException {
        bw.write("<p> The following Issues, where found, but are not directly linked to Log Messages:");
        bw.write("<ul>");
        for(ValidationException v : validationErrors){
            if(!(v instanceof LogMessageValidationException)){

                if(!issuesToIgnore.contains(v.getClass())) {
                    bw.write("<li>" + v.toString() + "</li>");
                }
            }
        }
        bw.write("</ul></p>");

    }

    void printLogMessageDetails(BufferedWriter bw, Collection<LogMessageArchive> logs, ValidationResult vResult) throws IOException {
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
        bw.write("<p> LogMessages:<br>");

        if(skipLegitLogMessages){
            bw.write("(legit log messages were skipped in this report)<br>");
        }
        bw.write("<ul>");

        for(LogMessageArchive tar : logs){
            for (LogMessage lm : tar.getSortedLogMessages()){
                if(!map.containsKey(lm)){
                    if(!skipLegitLogMessages) {
                        bw.write("<li>" + lm.getFileName() + " seems legit.</li>");
                    }
                }else{
                    bw.write("<li>");
                    bw.write("Found the following issues while validating "+lm.getFileName()+":");
                    bw.write("<ul>");
                    for(LogMessageValidationException e : map.get(lm)) {
                        bw.write("<li>" + e.toString() + "</li>");
                    }
                    bw.write("</ul>");
                    bw.write("</li>");
                }

            }
        }
    }

    void printErrorNum(BufferedWriter bw, Collection<ValidationException> validationErrors) throws IOException {
        bw.write("<p> While validating, "+validationErrors.size()+" errors were found. </p>");
    }

    void printTars(BufferedWriter bw, Collection<LogMessageArchive> logs) throws IOException {
        bw.write("<p> This report covers the following LogMessage Archives:");
        bw.write("<ul>");

        for(LogMessageArchive l: logs){
            bw.write("<li>"+l.getFileName()+"</li>");
        }

        bw.write("</ul></p>");
    }


    void printValidators(BufferedWriter bw, Collection<Validator> validators) throws IOException {
        bw.write("<p> To generate this report, the following validators were used:");
        bw.write("<ul>");

        for(Validator v: validators){
            bw.write("<li>"+v.getClass()+"</li>");
        }
        bw.write("</ul></p>");
    }


    static void printHeader(BufferedWriter bw) throws IOException {
        bw.write("<html><head><title>Report</title></head><body>");
    }

    static void printFooter(BufferedWriter bw) throws IOException {
        bw.write("</body></html>");
    }
}
