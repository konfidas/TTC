//package de.konfidas.ttc.reporting;
//
//import de.konfidas.ttc.messages.LogMessage;
//import de.konfidas.ttc.messages.TransactionLogMessage;
//import org.apache.commons.codec.binary.Hex;
//import org.bouncycastle.asn1.ASN1Primitive;
//
//public class LogMessageReporter extends ReportTree<LogMessage> {
//        public LogMessageReporter(LogMessage log) {
//            super(log.getFileName(), log);
//            createReport();
//        }
//
//
//        void createReport() {
//            LogMessage msg = this.getData();
//
//            addChild(new ReportTree("version", msg.getVersion()));
//            addChild(new ReportTree("certifiedDataType", msg.getCertifiedDataType()));
//            if (msg instanceof TransactionLogMessage){
//                reportCertifiedDataOfTransactionLogMessage((TransactionLogMessage) msg);
//            }
//
//            addChild(new ReportTree("serialNumber", Hex.encodeHexString(msg.getSerialNumber())));
//
//            reportSignatureAlgorithm();
//            reportSeAuditData();
//
//            addChild(new ReportTree("signatureCounter", msg.getSignatureCounter()));
//            addChild(new ReportTree("LogTimeFormat", msg.getLogTime().getType()));
//            addChild(new ReportTree("LogTime", msg.getLogTime()));
//
//            reportSignatureData();
//
//        }
//
//        void reportCertifiedDataOfTransactionLogMessage(TransactionLogMessage msg) {
//            ReportTree certifiedDataReportTree = new ReportTree("certifiedData", "");
//            certifiedDataReportTree.addChild(new ReportTree("operationType", ((TransactionLogMessage) msg).getOperationType()));
//            certifiedDataReportTree.addChild(new ReportTree("clientID", ((TransactionLogMessage) msg).getClientID()));
//            certifiedDataReportTree.addChild(new ReportTree("processData", Hex.encodeHexString(((TransactionLogMessage) msg).getProcessData())));
//            certifiedDataReportTree.addChild(new ReportTree("processType", ((TransactionLogMessage) msg).getProcessType()));
//            if (((TransactionLogMessage) msg).getAdditionalExternalData() == null){
//                certifiedDataReportTree.addChild(new ReportTree("additionalExternalData", "none"));
//            }else {
//                certifiedDataReportTree.addChild(new ReportTree("additionalExternalData", Hex.encodeHexString(((TransactionLogMessage) msg).getAdditionalExternalData())));
//            }
//            certifiedDataReportTree.addChild(new ReportTree("transactionNumber", ((TransactionLogMessage) msg).getTransactionNumber()));
//
//            if (msg.getAdditionalInternalData() == null) {
//                certifiedDataReportTree.addChild(new ReportTree("additionalInternalData", "none"));
//            }else {
//                certifiedDataReportTree.addChild(new ReportTree("additionalInternalData", Hex.encodeHexString(((TransactionLogMessage) msg).getAdditionalInternalData())));
//            }
//            this.addChild(certifiedDataReportTree);
//        }
//
//        void reportSignatureAlgorithm() {
//            LogMessage msg = this.getData();
//            ReportTree signatureAlgorithmReportTree = new ReportTree("signatureAlgorithm", "");
//
//            signatureAlgorithmReportTree.addChild(new ReportTree("signatureAlgorithm", msg.getSignatureAlgorithm()));
//            for (ASN1Primitive signatureAlgorithmParameter : msg.getSignatureAlgorithmParameters()) {
//                signatureAlgorithmReportTree.addChild(new ReportTree("signatureAlgorithmParameter", signatureAlgorithmParameter));
//            }
//            this.addChild(signatureAlgorithmReportTree);
//        }
//
//        void reportSeAuditData() {
//            LogMessage msg = this.getData();
//            ReportTree seAuditDataReportTree;
//            if (msg.getSeAuditData() != null) {
//                seAuditDataReportTree = new ReportTree("seAuditData", "");
//                seAuditDataReportTree.addChild(new ReportTree("seAuditData",Hex.encodeHexString(msg.getSeAuditData())));
//            } else {
//                seAuditDataReportTree = new ReportTree("seAuditData", "none");
//            }
//           this.addChild(seAuditDataReportTree);
//        }
//
//        void reportSignatureData() {
//            LogMessage msg = this.getData();
//            ReportTree signatureDataReportTree = new ReportTree("signatureData","");
//
//            signatureDataReportTree.addChild(new ReportTree("signatureValue",Hex.encodeHexString(msg.getSignatureValue())));
//            signatureDataReportTree.addChild(new ReportTree("dtbs",Hex.encodeHexString(msg.getDTBS())));
//
//            this.addChild(signatureDataReportTree);
//        }
//
//        @Override
//        public String toString(){
//            return ReportTreeTextPrinter.printReportToText(this,1);
//        }
//    };
//
//
//}