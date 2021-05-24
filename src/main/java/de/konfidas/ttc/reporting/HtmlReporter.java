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
        bw.write("<h1 id=\"generalerrors\">General errors</h1>\n");
        bw.write("<p> The following Issues, where found, but are not directly linked to Log Messages:</p>");
        bw.write("<ul>");
        for(ValidationException v : validationErrors){
            if(!(v instanceof LogMessageValidationException)){

                if(!issuesToIgnore.contains(v.getClass())) {
                    bw.write("<li>" + v.toString() + "</li>");
                }
            }
        }
        bw.write("</ul>");

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
        bw.write("<h1 id=\"errors\">Errors</h1>\n");
        bw.write("<p> LogMessages:<br></p>");

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
        bw.write("<h1 id=\"logmessages\">Log Messages</h1>\n");
        bw.write("<p> This report covers the following LogMessage Archives:</p>");
        bw.write("<ul>");

        for(LogMessageArchive l: logs){
            bw.write("<li>"+l.getFileName()+"</li>");
        }

        bw.write("</ul>");
    }


    void printValidators(BufferedWriter bw, Collection<Validator> validators) throws IOException {
        bw.write("<h1 id=\"validators\">Validators</h1>\n");
        bw.write("<p> To generate this report, the following validators were used:</p>");
        bw.write("<ul>");

        for(Validator v: validators){
            bw.write("<li>"+v.getClass()+"</li>");
        }
        bw.write("</ul>");
    }


    static void printHeader(BufferedWriter bw) throws IOException {
        bw.write("<html><head><title>Report</title>");
        bw.write("<style> body { margin: 0; background-color: #f1f1f1; } ul.nav { list-style-type: none; margin: 0; padding: 0; width: 25%; background-color: #979695; position: fixed; height: 100%; overflow: auto; } ul.nav li a { display: block; color: #000; padding: 8px 0 8px 16px; text-decoration: none; } ul.nav li a.active { background-color: #f18643; color: white; } ul.nav li a:hover:not(.active) { background-color: #dcdcdc; color: white; } h1 { font-weight: bold; color: #080807; font-size: 32px; margin: 0; } </style>");
        bw.write("</head><body>");
        bw.write("<ul class=\"nav\"> <li><a class=\"active\" href=\"#logmessages\">Log Messages</a></li> <li><a href=\"#validators\">Applied Validators</a></li> <li><a href=\"#generalerrors\">General errors</a></li> <li><a href=\"#errors\">Errors on log messages</a></li> </ul>" +
                ">");
        bw.write("<div style=\"margin-left:25%;padding:1px;\">\n");
    }

    static void printFooter(BufferedWriter bw) throws IOException {
        bw.write("</div></body></html>");
    }
}
