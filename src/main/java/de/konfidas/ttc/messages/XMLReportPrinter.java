//package de.konfidas.ttc.messages;
//
//import org.apache.commons.codec.binary.Hex;
//import org.bouncycastle.asn1.ASN1Primitive;
//import org.w3c.dom.Document;
//import org.w3c.dom.Element;
//
//import javax.xml.parsers.DocumentBuilder;
//import javax.xml.parsers.DocumentBuilderFactory;
//import javax.xml.transform.OutputKeys;
//import javax.xml.transform.Transformer;
//import javax.xml.transform.TransformerException;
//import javax.xml.transform.TransformerFactory;
//import javax.xml.transform.dom.DOMSource;
//import javax.xml.transform.stream.StreamResult;
//import java.io.StringWriter;
//
//public class XMLReportPrinter extends Report {
//    DocumentBuilderFactory dbf;
//    Document dom;
//    Element e;
//    Element rootEle;
//
//
//    public XMLReportPrinter(String rootElementName){
//
//        // instance of a DocumentBuilderFactory
//         dbf = DocumentBuilderFactory.newInstance();
//        DocumentBuilder db = dbf.newDocumentBuilder();
//        // create instance of DOM
//        dom = db.newDocument();
//
//         rootEle= dom.createElement(rootElementName);
//
//    }
//
//    void printReportToString(){
//        dom.appendChild(rootEle);
//
//        try {
//            Transformer tr = TransformerFactory.newInstance().newTransformer();
//            tr.setOutputProperty(OutputKeys.INDENT, "yes");
//            tr.setOutputProperty(OutputKeys.METHOD, "xml");
//            tr.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
//            tr.setOutputProperty(OutputKeys.DOCTYPE_SYSTEM, "roles.dtd");
//            tr.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
//
//            // send DOM to file
//            StringWriter writer = new StringWriter();
//
//            //transform document to string
//            tr.transform(new DOMSource(dom), new StreamResult(writer));
//
//            String xmlString = writer.getBuffer().toString();
//            System.out.println(xmlString);
//
//
////            tr.transform(new DOMSource(dom), new StreamResult(new FileOutputStream(xml)));
//
//        } catch (TransformerException te) {
//            System.out.println(te.getMessage());
//        }
//    }
//    void reportText(String info){
//
//
//            // create data elements and place them under root
//            e = dom.createElement(info);
//            e.appendChild(dom.createTextNode(info));
//            rootEle.appendChild(e);
//
//    }
//    static public String printMessage(LogMessage msg) {
//        StringBuilder return_value = new StringBuilder(String.format("The following log message has been extracted from file %s", msg.getFileName()));
//        return_value.append(System.lineSeparator());
//        return_value.append(String.format("version: %d", msg.getVersion()));
//        return_value.append( System.lineSeparator());
//        return_value.append(String.format("certifiedDataType: %s", msg.getCertifiedDataType()));
//        return_value.append( System.lineSeparator());
//
//        if (msg instanceof TransactionLogMessage){return_value.append(printCertifiedDataOfTransactionLogMessage(msg)); }
//
//        return_value.append(String.format("serialNumber: %s", Hex.encodeHexString(msg.getSerialNumber())));
//        return_value.append(System.lineSeparator());
//
//        printSignatureAlgorithm(msg);
//
//        printSeAuditData(msg);
//
//        return_value.append(String.format("signatureCounter: %d", msg.getSignatureCounter()));
//        return_value.append(System.lineSeparator());
//
//        return_value.append(String.format("logTimeFormat:: %s", msg.getLogTime().getType()));
//        return_value.append(System.lineSeparator());
//        return_value.append(String.format("logTime: %s", msg.getLogTime().toString()));
//
//        printSignatureData(msg);
//
//
//        return (return_value.toString());
//    }
//
//    static public String printCertifiedDataOfTransactionLogMessage(LogMessage msg) {
//        StringBuilder return_value = new StringBuilder();
//
//        return_value.append(String.format("[certifiedData]operationType: %s", ((TransactionLogMessage) msg).operationType));
//        return_value.append(System.lineSeparator());
//        return_value.append(String.format("[certifiedData]clientID: %s", ((TransactionLogMessage) msg).clientID));
//        return_value.append(System.lineSeparator());
//        return_value.append(String.format("[certifiedData]processData: %s",Hex.encodeHexString(((TransactionLogMessage)msg).processData)));
//        return_value.append(System.lineSeparator());
//        return_value.append(String.format("[certifiedData]processType: %s", ((TransactionLogMessage) msg).processType));
//        return_value.append(System.lineSeparator());
//        return_value.append((((TransactionLogMessage)msg).additionalExternalData == null) ? "[certifiedData]No additionalExternalData" : String.format("[certifiedData]additionalExternaData: %s",Hex.encodeHexString(((TransactionLogMessage)msg).additionalExternalData)));
//        return_value.append(System.lineSeparator());
//        return_value.append(String.format("[certifiedData]transactionNumber: %x", ((TransactionLogMessage) msg).transactionNumber));
//        return_value.append(System.lineSeparator());
//        return_value.append((((TransactionLogMessage)msg).additionalInternalData == null) ? "[certifiedData]No additionalInternalData" : String.format("[certifiedData]additionalInternalData: %s",Hex.encodeHexString(((TransactionLogMessage)msg).additionalInternalData)));
//        return_value.append(System.lineSeparator());
//        return_value.append(System.lineSeparator());
//
//        return(return_value.toString());
//
//    }
//
//    static public String printSignatureAlgorithm(LogMessage msg) {
//        StringBuilder return_value = new StringBuilder();
//
//        return_value.append(String.format("signatureAlgorithm: %s", msg.getSignatureAlgorithm()));
//        return_value.append(System.lineSeparator());
//
//        for (ASN1Primitive signatureAlgorithmParameter : msg.getSignatureAlgorithmParameters()) {
//            return_value.append(String.format("signatureAlgorithmParameter: %s", signatureAlgorithmParameter.toString()));
//            return_value.append(System.lineSeparator());
//        }
//
//        return(return_value.toString());
//
//    }
//
//    static public String printSeAuditData(LogMessage msg) {
//        StringBuilder return_value = new StringBuilder();
//
//        if (msg.getSeAuditData() != null) {
//            return_value.append(String.format("seAuditData: %s", Hex.encodeHexString(msg.getSeAuditData())));
//            return_value.append(System.lineSeparator());
//        }
//
//
//        return(return_value.toString());
//
//    }
//
//    static public String printSignatureData(LogMessage msg) {
//        StringBuilder return_value = new StringBuilder();
//
//        return_value.append(String.format("signatureValue:: %s", Hex.encodeHexString(msg.getSignatureValue())));
//        return_value.append(System.lineSeparator());
//
//        return_value.append(String.format("dtbs:: %s", Hex.encodeHexString(msg.getDTBS())));
//        return_value.append(System.lineSeparator());
//
//        return(return_value.toString());
//
//    }
//}
