package de.konfidas.ttc.reporting;

import de.konfidas.ttc.exceptions.LogMessageValidationException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.TransactionLogMessage;
import de.konfidas.ttc.tars.LogMessageArchive;
import de.konfidas.ttc.validation.ValidationResult;
import de.konfidas.ttc.validation.Validator;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Primitive;

import java.io.*;
import java.nio.Buffer;
import java.nio.file.Files;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.stream.Collectors;

public class HtmlReporter implements Reporter<String> {
    File file;
    boolean skipLegitLogMessages;
    HashSet<Class<? extends ValidationException>> issuesToIgnore;

    public HtmlReporter(){
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
    public String createReport(Collection<LogMessageArchive> logs, ValidationResult vResult, Boolean skipLegitLogMessages) throws ReporterException {
        this.skipLegitLogMessages = skipLegitLogMessages;
        try(StringWriter sw = new StringWriter();){
            printHeader(sw);

            printTars(sw, logs);
            printValidators(sw,vResult.getValidators());

            printErrorNum(sw, vResult.getValidationErrors());

            printNonLogMessageValidationExceptions(sw, vResult.getValidationErrors());

            printLogMessageDetails(sw, logs, vResult);

            printFooter(sw);
            return sw.toString();
        } catch (IOException e) {
            throw new ReporterException("Fehler bei der Erstellung des HTML Reports",e);
        }

    }

    void printNonLogMessageValidationExceptions(StringWriter sw, Collection<ValidationException> validationErrors) throws IOException {
        sw.write("<h1 id=\"generalerrors\">General errors</h1>\n");
        long numberOfGeneralValidationExceptions = validationErrors.stream().filter(c -> !(c instanceof LogMessageValidationException)).count();
        if (numberOfGeneralValidationExceptions>0)
            sw.write("<p> The following Issues, where found, but are not directly linked to Log Messages:</p>");
        else
            sw.write("<p>None</p>");

        sw.write("<ul>");
        for(ValidationException v : validationErrors){
            if(!(v instanceof LogMessageValidationException)){

                if(!issuesToIgnore.contains(v.getClass())) {
                    sw.write("<li>" + v.toString() + "</li>");
                }
            }
        }
        sw.write("</ul>");

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
        sw.write("<h1 id=\"errors\">Errors for log messages</h1>\n");

        if(skipLegitLogMessages){
            sw.write("(legit log messages were skipped in this report)<br>");
        }

        for(LogMessageArchive tar : logs){
            for (LogMessage lm : tar.getSortedLogMessages()){
                if(!map.containsKey(lm)){
                    if(!skipLegitLogMessages) {
                        sw.write("<li>" + lm.getFileName() + " seems legit.</li>");
                    }
                }else{
                    sw.write("Found the following issues while validating "+lm.getFileName()+":");
                    sw.write("<ul>");
                    for(LogMessageValidationException e : map.get(lm)) {
                        sw.write("<li>" + e.toString() + "</li>");
                    }
                    sw.write("</ul>");
                    sw.write("<button type=\"button\" class=\"accordion\">Click here for the complete content of "+lm.getFileName()+"</button>");
                    sw.write("<div class=\"panel\">");

                    sw.write("<table>");
                    printLogMessage(lm, sw);
                    sw.write("</table>");
                    sw.write(" </div>");

                }

            }
        }
    }

    void printErrorNum(StringWriter sw, Collection<ValidationException> validationErrors) throws IOException {
        sw.write("<p> While validating, "+validationErrors.size()+" errors were found. </p>");
    }

    void printTars(StringWriter sw, Collection<LogMessageArchive> logs) throws IOException {
        sw.write("<h1 id=\"logmessages\">Log Messages</h1>\n");
        sw.write("<p> This report covers the following LogMessage Archives:</p>");
        sw.write("<ul>");

        for(LogMessageArchive l: logs){
            sw.write("<li>"+l.getFileName()+"</li>");
        }

        sw.write("</ul>");
    }


    void printValidators(StringWriter sw, Collection<Validator> validators) throws IOException {
        sw.write("<h1 id=\"validators\">Validators</h1>\n");
        sw.write("<p> To generate this report, the following validators were used:</p>");
        sw.write("<ul>");

        for(Validator v: validators){
            sw.write("<li>"+v.getClass()+"</li>");
        }
        sw.write("</ul>");
    }


    static void printHeader(StringWriter sw) throws IOException {
        String fileName = "report.css";
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        File file = new File(classLoader.getResource(fileName).getFile());
        String cssString = new String(Files.readAllBytes(file.toPath()));


        sw.write("<html><head><title>Report</title>");
        sw.write("<style>");
        sw.write(cssString);
        sw.write("</style>");
        sw.write("</head><body>");
        sw.write("<ul class=\"nav\"> <li><a class=\"active\" href=\"#logmessages\">Log Messages</a></li> <li><a href=\"#validators\">Applied Validators</a></li> <li><a href=\"#generalerrors\">General errors</a></li> <li><a href=\"#errors\">Errors on log messages</a></li> </ul>" +
                ">");
        sw.write("<div style=\"margin-left:25%;padding:1px;\">\n");
    }

    static void printFooter(StringWriter sw) throws IOException {
        sw.write("</div>");
        sw.write("<script>var acc = document.getElementsByClassName(\"accordion\"); var i; for (i = 0; i < acc.length; i++) { acc[i].addEventListener(\"click\", function() { this.classList.toggle(\"active\"); var panel = this.nextElementSibling; if (panel.style.maxHeight) { panel.style.maxHeight = null; } else { panel.style.maxHeight = panel.scrollHeight + \"px\"; } }); }</script>");
        sw.write("</body></html>");
    }

    static void printLogMessage(LogMessage msg, StringWriter sw) throws IOException {

        sw.write("<tr><td>version:</td><td>"+ msg.getVersion()+"</td></tr>");
        sw.write("<tr><td>certifiedDataType:</td><td>"+ msg.getCertifiedDataType().toString()+"</td></tr>");

        if (msg instanceof TransactionLogMessage){
            reportCertifiedDataOfTransactionLogMessage((TransactionLogMessage) msg, sw);
        }
        sw.write("serialNumber: "+Hex.encodeHexString(msg.getSerialNumber()));

        sw.write("<tr><td>signatureCounter:</td><td>"+ msg.getSignatureCounter().toString()+"</td></tr>");
        sw.write("<tr><td>LogTimeFormat:</td><td>"+ msg.getLogTime().getType().toString()+"</td></tr>");
        sw.write("<tr><td>LogTime:</td><td>"+ msg.getLogTime().toString()+"</td></tr>");


    }


    static void reportCertifiedDataOfTransactionLogMessage(TransactionLogMessage msg, StringWriter sw) throws IOException {
        sw.write("todo");
//        ReportTree certifiedDataReportTree = new ReportTree("certifiedData", "");
//        certifiedDataReportTree.addChild(new ReportTree("operationType", ((TransactionLogMessage) msg).getOperationType()));
//        certifiedDataReportTree.addChild(new ReportTree("clientID", ((TransactionLogMessage) msg).getClientID()));
//        certifiedDataReportTree.addChild(new ReportTree("processData", Hex.encodeHexString(((TransactionLogMessage) msg).getProcessData())));
//        certifiedDataReportTree.addChild(new ReportTree("processType", ((TransactionLogMessage) msg).getProcessType()));
//        if (((TransactionLogMessage) msg).getAdditionalExternalData() == null){
//            certifiedDataReportTree.addChild(new ReportTree("additionalExternalData", "none"));
//        }else {
//            certifiedDataReportTree.addChild(new ReportTree("additionalExternalData", Hex.encodeHexString(((TransactionLogMessage) msg).getAdditionalExternalData())));
//        }
//        certifiedDataReportTree.addChild(new ReportTree("transactionNumber", ((TransactionLogMessage) msg).getTransactionNumber()));
//
//        if (msg.getAdditionalInternalData() == null) {
//            certifiedDataReportTree.addChild(new ReportTree("additionalInternalData", "none"));
//        }else {
//            certifiedDataReportTree.addChild(new ReportTree("additionalInternalData", Hex.encodeHexString(((TransactionLogMessage) msg).getAdditionalInternalData())));
//        }
//        this.addChild(certifiedDataReportTree);
    }
//    -------
//    void reportSignatureAlgorithm() {
//        LogMessage msg = this.getData();
//        ReportTree signatureAlgorithmReportTree = new ReportTree("signatureAlgorithm", "");
//
//        signatureAlgorithmReportTree.addChild(new ReportTree("signatureAlgorithm", msg.getSignatureAlgorithm()));
//        for (ASN1Primitive signatureAlgorithmParameter : msg.getSignatureAlgorithmParameters()) {
//            signatureAlgorithmReportTree.addChild(new ReportTree("signatureAlgorithmParameter", signatureAlgorithmParameter));
//        }
//        this.addChild(signatureAlgorithmReportTree);
//    }
//
//    void reportSeAuditData() {
//        LogMessage msg = this.getData();
//        ReportTree seAuditDataReportTree;
//        if (msg.getSeAuditData() != null) {
//            seAuditDataReportTree = new ReportTree("seAuditData", "");
//            seAuditDataReportTree.addChild(new ReportTree("seAuditData",Hex.encodeHexString(msg.getSeAuditData())));
//        } else {
//            seAuditDataReportTree = new ReportTree("seAuditData", "none");
//        }
//        this.addChild(seAuditDataReportTree);
//    }
//
//    void reportSignatureData() {
//        LogMessage msg = this.getData();
//        ReportTree signatureDataReportTree = new ReportTree("signatureData","");
//
//        signatureDataReportTree.addChild(new ReportTree("signatureValue",Hex.encodeHexString(msg.getSignatureValue())));
//        signatureDataReportTree.addChild(new ReportTree("dtbs",Hex.encodeHexString(msg.getDTBS())));
//
//        this.addChild(signatureDataReportTree);
//    }
//
//    @Override
//    public String toString(){
//        return ReportTreeTextPrinter.printReportToText(this,1);
//    }
//};
//
//------

}
