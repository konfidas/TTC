package de.konfidas.ttc.reporting;

import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.TransactionLogMessage;
import de.konfidas.ttc.tars.LogMessageArchive;
import de.konfidas.ttc.validation.ValidationResult;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Primitive;

import java.util.Collection;

public class LogMessageReporter implements Reporter<Report<?>> {
    public LogMessageReporter(){
    }

    @Override
    public Report<?> createReport(Collection<LogMessageArchive> logs, ValidationResult vResult) {

        Report<?> report = new Report("",null);

        for(LogMessageArchive tar : logs){
            for(LogMessage log : tar.getLogMessages()){
                report.addChild(new LogMessageReport(log));
            }
        }

        return report;
    }

    public static class LogMessageReport extends Report<LogMessage>{
        public LogMessageReport(LogMessage log) {
            super(log.getFileName(), log);
            createReport();
        }


        void createReport() {
            LogMessage msg = this.getData();

            addChild(new Report("version", msg.getVersion()));
            addChild(new Report("certifiedDataType", msg.getCertifiedDataType()));
            if (msg instanceof TransactionLogMessage){
                reportCertifiedDataOfTransactionLogMessage((TransactionLogMessage) msg);
            }

            addChild(new Report("serialNumber", Hex.encodeHexString(msg.getSerialNumber())));

            reportSignatureAlgorithm();
            reportSeAuditData();

            addChild(new Report("signatureCounter", msg.getSignatureCounter()));
            addChild(new Report("LogTimeFormat", msg.getLogTime().getType()));
            addChild(new Report("LogTime", msg.getLogTime()));

            reportSignatureData();

        }

        void reportCertifiedDataOfTransactionLogMessage(TransactionLogMessage msg) {
            Report certifiedDataReport = new Report("certifiedData", "");
            certifiedDataReport.addChild(new Report("operationType", ((TransactionLogMessage) msg).getOperationType()));
            certifiedDataReport.addChild(new Report("clientID", ((TransactionLogMessage) msg).getClientID()));
            certifiedDataReport.addChild(new Report("processData", Hex.encodeHexString(((TransactionLogMessage) msg).getProcessData())));
            certifiedDataReport.addChild(new Report("processType", ((TransactionLogMessage) msg).getProcessType()));
            if (((TransactionLogMessage) msg).getAdditionalExternalData() == null){
                certifiedDataReport.addChild(new Report("additionalExternalData", "none"));
            }else {
                certifiedDataReport.addChild(new Report("additionalExternalData", Hex.encodeHexString(((TransactionLogMessage) msg).getAdditionalExternalData())));
            }
            certifiedDataReport.addChild(new Report("transactionNumber", ((TransactionLogMessage) msg).getTransactionNumber()));

            if (msg.getAdditionalInternalData() == null) {
                certifiedDataReport.addChild(new Report("additionalInternalData", "none"));
            }else {
                certifiedDataReport.addChild(new Report("additionalInternalData", Hex.encodeHexString(((TransactionLogMessage) msg).getAdditionalInternalData())));
            }
            this.addChild(certifiedDataReport);
        }

        void reportSignatureAlgorithm() {
            LogMessage msg = this.getData();
            Report signatureAlgorithmReport = new Report("signatureAlgorithm", "");

            signatureAlgorithmReport.addChild(new Report("signatureAlgorithm", msg.getSignatureAlgorithm()));
            for (ASN1Primitive signatureAlgorithmParameter : msg.getSignatureAlgorithmParameters()) {
                signatureAlgorithmReport.addChild(new Report("signatureAlgorithmParameter", signatureAlgorithmParameter));
            }
            this.addChild(signatureAlgorithmReport);
        }

        void reportSeAuditData() {
            LogMessage msg = this.getData();
            Report seAuditDataReport;
            if (msg.getSeAuditData() != null) {
                seAuditDataReport = new Report("seAuditData", "");
                seAuditDataReport.addChild(new Report("seAuditData",Hex.encodeHexString(msg.getSeAuditData())));
            } else {
                seAuditDataReport = new Report("seAuditData", "none");
            }
           this.addChild(seAuditDataReport);
        }

        void reportSignatureData() {
            LogMessage msg = this.getData();
            Report signatureDataReport = new Report("signatureData","");

            signatureDataReport.addChild(new Report("signatureValue",Hex.encodeHexString(msg.getSignatureValue())));
            signatureDataReport.addChild(new Report("dtbs",Hex.encodeHexString(msg.getDTBS())));

            this.addChild(signatureDataReport);
        }

        @Override
        public String toString(){
            return ReportTextPrinter.printReportToText(this,1);
        }
    };


}