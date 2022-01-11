package de.konfidas.ttc.reporting;

import de.konfidas.ttc.exceptions.LogMessageValidationException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.TransactionLogMessage;
import de.konfidas.ttc.tars.LogMessageArchive;
import de.konfidas.ttc.validation.ValidationResult;
import de.konfidas.ttc.validation.Validator;
import org.apache.commons.codec.binary.Hex;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.util.*;

public class HtmlReporter implements Reporter<String> {

    static Locale locale = new Locale("de", "DE"); //NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc", locale); //NON-NLS
    boolean skipLegitLogMessages;
    HashSet<Class<? extends ValidationException>> issuesToIgnore;

    public HtmlReporter() {
        this.issuesToIgnore = new HashSet<>();
        skipLegitLogMessages = false;
    }

    HtmlReporter skipLegitLogMessages() {
        skipLegitLogMessages = true;
        return this;
    }

    HtmlReporter skipLegitLogMessages(boolean skipLegitLogMessages) {
        this.skipLegitLogMessages = skipLegitLogMessages;
        return this;
    }

    HtmlReporter ignoreIssue(Class<? extends ValidationException> t) {
        issuesToIgnore.add(t);
        return this;
    }

    HtmlReporter ignoreIssues(Collection<Class<? extends ValidationException>> c) {
        issuesToIgnore.addAll(c);
        return this;
    }

    @Override
    public String createReport(Collection<LogMessageArchive> logs, ValidationResult vResult, Boolean skipLegitLogMessages) throws ReporterException {
        this.skipLegitLogMessages = skipLegitLogMessages;
        try (StringWriter sw = new StringWriter()) {
            printHeader(sw);

            printTars(sw, logs);
            printValidators(sw, vResult.getValidators());

            printErrorNum(sw, vResult.getValidationErrors());

            printNonLogMessageValidationExceptions(sw, vResult.getValidationErrors());

            printLogMessageDetails(sw, logs, vResult);

            printFooter(sw);
            return sw.toString();
        } catch (IOException e) {
            throw new ReporterException(properties.getString("de.konfidas.ttc.reporting.errorCreatingHTMLReport"), e);
        }

    }

    void printNonLogMessageValidationExceptions(StringWriter sw, Collection<ValidationException> validationErrors) throws IOException {
        sw.write(properties.getString("de.konfidas.ttc.reporting.HtmlHeadlineGeneralErrors"));
        long numberOfGeneralValidationExceptions = validationErrors.stream().filter(c -> !(c instanceof LogMessageValidationException)).count();
        if (numberOfGeneralValidationExceptions > 0)
            sw.write(properties.getString("de.konfidas.ttc.reporting.htmlReportIntroductionToIssues"));
        else
            sw.write(properties.getString("de.konfidas.ttc.reporting.htmlReportNone"));

        sw.write("<ul>");//NON-NLS
        for (ValidationException v : validationErrors) {
            if (!(v instanceof LogMessageValidationException)) {

                if (!issuesToIgnore.contains(v.getClass())) {
                    sw.write("<li>" + v.toString() + "</li>");//NON-NLS
                }
            }
        }
        sw.write("</ul>");//NON-NLS

    }

    void printLogMessageDetails(StringWriter sw, Collection<LogMessageArchive> logs, ValidationResult vResult) throws IOException {
        HashMap<LogMessage, LinkedList<LogMessageValidationException>> map = new HashMap<>();
        for (ValidationException e : vResult.getValidationErrors()) {
            if (e instanceof LogMessageValidationException) {
                if (!issuesToIgnore.contains(e.getClass())) {
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
        sw.write(properties.getString("de.konfidas.ttc.reporting.htmlHeadlineForLogMessageErrors"));

        if (skipLegitLogMessages) {
            sw.write(properties.getString("de.konfidas.ttc.reporting.htmlReportLegitMessagesWereSkipped"));
        }

        for (LogMessageArchive tar : logs) {
            for (LogMessage lm : tar.getSortedLogMessages()) {
                if (!map.containsKey(lm)) {
                    if (!skipLegitLogMessages) {
                        sw.write(String.format(properties.getString("de.konfidas.ttc.reporting.logMessageIsValid"), lm.getFileName()));
                    }
                } else {
                    sw.write(String.format(properties.getString("de.konfidas.ttc.reporting.introductionErrorsHTMLReport"), lm.getFileName()));
                    sw.write("<ul>");//NON-NLS
                    for (LogMessageValidationException e : map.get(lm)) {
                        sw.write("<li>" + e.toString() + "</li>");//NON-NLS
                    }
                    sw.write("</ul>");//NON-NLS
                    sw.write(String.format(properties.getString("de.konfidas.ttc.reporting.clickForCompleteContentOfLogMessage"), lm.getFileName()));
                    sw.write("<div class=\"panel\">");//NON-NLS

                    sw.write("<table>");//NON-NLS
                    printLogMessage(lm, sw);
                    sw.write("</table>");//NON-NLS
                    sw.write(" </div>");//NON-NLS

                }

            }
        }
    }

    void printErrorNum(StringWriter sw, Collection<ValidationException> validationErrors) throws IOException {
        sw.write(String.format(properties.getString("de.konfidas.ttc.reporting.introductionNumberOfErrors"), validationErrors.size()));
    }

    void printTars(StringWriter sw, Collection<LogMessageArchive> logs) throws IOException {
        sw.write("<h1 id=\"logmessages\">Log Messages</h1>\n");//NON-NLS
        sw.write(properties.getString("de.konfidas.ttc.reporting.reportCoversTheFollowingArchives"));
        sw.write("<ul>");//NON-NLS

        for (LogMessageArchive l : logs) {
            sw.write("<li>" + l.getFileName() + "</li>");//NON-NLS
        }

        sw.write("</ul>");//NON-NLS
    }


    void printValidators(StringWriter sw, Collection<Validator> validators) throws IOException {
        sw.write(properties.getString("de.konfidas.ttc.reporting.headlineValidators"));
        sw.write(properties.getString("de.konfidas.ttc.reporting.reportUsedValidators"));
        sw.write("<ul>");//NON-NLS

        for (Validator v : validators) {
            sw.write("<li>" + v.getClass() + "</li>");//NON-NLS
        }
        sw.write("</ul>");//NON-NLS
    }


    static void printHeader(StringWriter sw) throws IOException {
        String fileName = "report.css";
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        File file = new File(classLoader.getResource(fileName).getFile());
        String cssString = new String(Files.readAllBytes(file.toPath()));


        sw.write("<html><head><title>Report</title>");//NON-NLS
        sw.write("<style>");//NON-NLS
        sw.write(cssString);
        sw.write("</style>");//NON-NLS
        sw.write("</head><body>");//NON-NLS
        sw.write(properties.getString("de.konfidas.ttc.reporting.htmlMenu"));
//                + ">");
        sw.write("<div style=\"margin-left:25%;padding:1px;\">\n");//NON-NLS
    }

    static void printFooter(StringWriter sw) throws IOException {
        sw.write("</div>");//NON-NLS
        sw.write("<script>var acc = document.getElementsByClassName(\"accordion\"); var i; for (i = 0; i < acc.length; i++) { acc[i].addEventListener(\"click\", function() { this.classList.toggle(\"active\"); var panel = this.nextElementSibling; if (panel.style.maxHeight) { panel.style.maxHeight = null; } else { panel.style.maxHeight = panel.scrollHeight + \"px\"; } }); }</script>");//NON-NLS
        sw.write("</body></html>");//NON-NLS
    }

    static void printLogMessage(LogMessage msg, StringWriter sw) throws IOException {

        sw.write("<tr><td>version:</td><td>" + msg.getVersion() + "</td></tr>");//NON-NLS
        sw.write("<tr><td>certifiedDataType:</td><td>" + msg.getCertifiedDataType().toString() + "</td></tr>");//NON-NLS

        if (msg instanceof TransactionLogMessage) {
            reportCertifiedDataOfTransactionLogMessage((TransactionLogMessage) msg, sw);
        }
        sw.write("serialNumber: " + Hex.encodeHexString(msg.getSerialNumber()));//NON-NLS

        sw.write("<tr><td>signatureCounter:</td><td>" + msg.getSignatureCounter().toString() + "</td></tr>");//NON-NLS
        sw.write("<tr><td>LogTimeFormat:</td><td>" + msg.getLogTime().getType().toString() + "</td></tr>");//NON-NLS
        sw.write("<tr><td>LogTime:</td><td>" + msg.getLogTime().toString() + "</td></tr>");//NON-NLS


    }


    static void reportCertifiedDataOfTransactionLogMessage(TransactionLogMessage msg, StringWriter sw) throws IOException {
        sw.write("todo");//NON-NLS
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
