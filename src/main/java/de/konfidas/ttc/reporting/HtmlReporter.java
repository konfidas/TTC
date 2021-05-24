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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.Buffer;
import java.nio.file.Files;
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
        bw.write("<h1 id=\"errors\">Errors for log messages</h1>\n");

        if(skipLegitLogMessages){
            bw.write("(legit log messages were skipped in this report)<br>");
        }
//        bw.write("<ul>");

        for(LogMessageArchive tar : logs){
            for (LogMessage lm : tar.getSortedLogMessages()){
                if(!map.containsKey(lm)){
                    if(!skipLegitLogMessages) {
                        bw.write("<li>" + lm.getFileName() + " seems legit.</li>");
                    }
                }else{
                    bw.write("Found the following issues while validating "+lm.getFileName()+":");
                    bw.write("<ul>");
                    for(LogMessageValidationException e : map.get(lm)) {
                        bw.write("<li>" + e.toString() + "</li>");
                    }
                    bw.write("</ul>");
                    bw.write("<button type=\"button\" class=\"accordion\">Click here for the complete content of "+lm.getFileName()+"</button>");
                    bw.write("<div class=\"panel\">");

                    bw.write("<table>");
                    printLogMessage(lm, bw);
                    bw.write("</table>");
                    bw.write(" </div>");

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
        String fileName = "report.css";
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        File file = new File(classLoader.getResource(fileName).getFile());
        String cssString = new String(Files.readAllBytes(file.toPath()));


        bw.write("<html><head><title>Report</title>");
        bw.write("<style>");
        bw.write(cssString);
        bw.write("</style>");
        bw.write("</head><body>");
        bw.write("<ul class=\"nav\"> <li><a class=\"active\" href=\"#logmessages\">Log Messages</a></li> <li><a href=\"#validators\">Applied Validators</a></li> <li><a href=\"#generalerrors\">General errors</a></li> <li><a href=\"#errors\">Errors on log messages</a></li> </ul>" +
                ">");
        bw.write("<div style=\"margin-left:25%;padding:1px;\">\n");
    }

    static void printFooter(BufferedWriter bw) throws IOException {
        bw.write("</div>");
        bw.write("<script>var acc = document.getElementsByClassName(\"accordion\"); var i; for (i = 0; i < acc.length; i++) { acc[i].addEventListener(\"click\", function() { this.classList.toggle(\"active\"); var panel = this.nextElementSibling; if (panel.style.maxHeight) { panel.style.maxHeight = null; } else { panel.style.maxHeight = panel.scrollHeight + \"px\"; } }); }</script>");
        bw.write("</body></html>");
    }

    static void printLogMessage(LogMessage msg, BufferedWriter bw) throws IOException {

        bw.write("<tr><td>version:</td><td>"+ msg.getVersion()+"</td></tr>");
        bw.write("<tr><td>certifiedDataType:</td><td>"+ msg.getCertifiedDataType().toString()+"</td></tr>");

        if (msg instanceof TransactionLogMessage){
            reportCertifiedDataOfTransactionLogMessage((TransactionLogMessage) msg, bw);
        }
        bw.write("serialNumber: "+Hex.encodeHexString(msg.getSerialNumber()));

        bw.write("<tr><td>signatureCounter:</td><td>"+ msg.getSignatureCounter().toString()+"</td></tr>");
        bw.write("<tr><td>LogTimeFormat:</td><td>"+ msg.getLogTime().getType().toString()+"</td></tr>");
        bw.write("<tr><td>LogTime:</td><td>"+ msg.getLogTime().toString()+"</td></tr>");



//        reportSignatureData();

    }



    static void reportCertifiedDataOfTransactionLogMessage(TransactionLogMessage msg, BufferedWriter bw) throws IOException {
        bw.write("todo");
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
