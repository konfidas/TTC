package de.konfidas.ttc.reporting;

import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.TransactionLogMessage;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Primitive;

public class LogMessageReporter extends Report {

    public LogMessageReporter(LogMessage msg) {
        super(msg.getFileName(), msg);
        this.reportMessage(msg);
    }

    public void reportMessage(LogMessage msg) {
        super.addChild(new Report("version", msg.getVersion()));
        super.addChild(new Report("certifiedDataType", msg.getCertifiedDataType()));
        if (msg instanceof TransactionLogMessage) super.addChild(reportCertifiedDataOfTransactionLogMessage(msg));

        super.addChild(new Report("serialNumber", Hex.encodeHexString(msg.getSerialNumber())));

        super.addChild(reportSignatureAlgorithm(msg));
        super.addChild(reportSeAuditData(msg));

        super.addChild(new Report("signatureCounter", msg.getSignatureCounter()));
        super.addChild(new Report("LogTimeFormat", msg.getLogTime().getType()));
        super.addChild(new Report("LogTime", msg.getLogTime()));

        super.addChild(reportSignatureData(msg));

    }

    public Report reportCertifiedDataOfTransactionLogMessage(LogMessage msg) {
        Report certifiedDataReport = new Report("certifiedData", "");
        certifiedDataReport.addChild(new Report("operationType", ((TransactionLogMessage) msg).getOperationType()));
        certifiedDataReport.addChild(new Report("clientID", ((TransactionLogMessage) msg).getClientID()));
        certifiedDataReport.addChild(new Report("processData", Hex.encodeHexString(((TransactionLogMessage) msg).getProcessData())));
        certifiedDataReport.addChild(new Report("processType", ((TransactionLogMessage) msg).getProcessType()));
        if (((TransactionLogMessage) msg).getAdditionalExternalData() == null)
            certifiedDataReport.addChild(new Report("additionalExternalData", "none"));
        else
            certifiedDataReport.addChild(new Report("additionalExternalData", Hex.encodeHexString(((TransactionLogMessage) msg).getAdditionalExternalData())));

        certifiedDataReport.addChild(new Report("transactionNumber", ((TransactionLogMessage) msg).getTransactionNumber()));

        if (((TransactionLogMessage) msg).getAdditionalInternalData() == null)
            certifiedDataReport.addChild(new Report("additionalInternalData", "none"));
        else
            certifiedDataReport.addChild(new Report("additionalInternalData", Hex.encodeHexString(((TransactionLogMessage) msg).getAdditionalInternalData())));

        return certifiedDataReport;
    }


    public Report reportSignatureAlgorithm(LogMessage msg) {
        Report signatureAlgorithmReport = new Report("signatureAlgorithm", "");
        signatureAlgorithmReport.addChild(new Report("signatureAlgorithm", msg.getSignatureAlgorithm()));
        for (ASN1Primitive signatureAlgorithmParameter : msg.getSignatureAlgorithmParameters()) {
            signatureAlgorithmReport.addChild(new Report("signatureAlgorithmParameter", signatureAlgorithmParameter));
        }
        return signatureAlgorithmReport;
    }

     public Report reportSeAuditData(LogMessage msg) {
        Report seAuditDataReport;
         if (msg.getSeAuditData() != null) {
              seAuditDataReport = new Report("seAuditData", "");
         seAuditDataReport.addChild(new Report("seAuditData",Hex.encodeHexString(msg.getSeAuditData())));
         }
         else
             seAuditDataReport = new Report("seAuditData", "none");

         return  seAuditDataReport;

     }

     public Report reportSignatureData(LogMessage msg) {
         Report signatureDataReport = new Report("signatureData","");

         signatureDataReport.addChild(new Report("signatureValue",Hex.encodeHexString(msg.getSignatureValue())));
         signatureDataReport.addChild(new Report("dtbs",Hex.encodeHexString(msg.getDTBS())));

         return signatureDataReport;

     }

}