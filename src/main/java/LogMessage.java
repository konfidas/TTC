
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.*;

import java.math.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Diese Klasse repräsentiert eine LogMessage. Der Konstruktur erhält den Inhalt der LogMessage und den Dateinamen, aus der
 * die LogMessage gelesen wurde. Die LogMessage wird geparst. Dabei wird das folgende Format erwartet
 * // ╔═══════════════════════╤══════╤══════════════════════════════════╤════════════╗
 * // ║ Data field            │ Tag  │ Data Type                        │ Mandatory? ║
 * // ╠═══════════════════════╪══════╪══════════════════════════════════╪════════════╣
 * // ║ LogMessage            │ 0x30 │ SEQUENCE                         │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    version            │ 0x02 │ INTEGER                          │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    certifiedDataType  │ 0x06 │ OBJECT IDENTIFIER                │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    certifiedData      │      │ ANY DEFINED BY certifiedDataType │ o          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    serialNumber       │ 0x04 │ OCTET STRING                     │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    signatureAlgorithm │ 0x30 │ SEQUENCE                         │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║       algorithm       │ 0x06 │ OBJECT IDENTIFIER                │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║       parameters      │      │ ANY DEFINED BY algorithm         │ o          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    seAuditData        │ 0x04 │ OCTET STRING                     │ c          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    signatureCounter   │ 0x02 │ INTEGER                          │ c          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    logTime            │      │ CHOICE                           │ m          ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║       utcTime         │ 0x17 │ UTCTime                          │            ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║       generalizedTime │ 0x18 │ GeneralizedTime                  │            ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║       unixTime        │ 0x02 │ INTEGER                          │            ║
 * // ╟───────────────────────┼──────┼──────────────────────────────────┼────────────╢
 * // ║    signatureValue     │ 0x04 │ OCTET STRING                     │ m          ║
 * // ╚═══════════════════════╧══════╧══════════════════════════════════╧════════════╝
 */
public class LogMessage {
    final static Logger logger = LoggerFactory.getLogger(TTC.class);

    int version = 0;
    String[] allowedCertifiedDataType = {"0.4.0.127.0.7.3.7.1.1", "0.4.0.127.0.7.3.7.1.2", "0.4.0.127.0.7.3.7.1.3"};
    String[] allowedAlgorithms = {"0.4.0.127.0.7.1.1.4.1.2", "0.4.0.127.0.7.1.1.4.1.3","0.4.0.127.0.7.1.1.4.1.4"};
//FIXME:
//   | ecdsa-plain-SHA512 | ecdsa-plain-SHA3-224 | ecdsa-plain-SHA3-256 | ecdsa-plain-SHA3-384 | ecdsa-plain-SHA3-512 | ecsdsa-plain-SHA224 | ecsdsa-plain-SHA256 | ecsdsa-plain-SHA384 | ecsdsa-plain-SHA512 | ecsdsa-plain-SHA3-224 | ecsdsa-plain-SHA3-256 | ecsdsa-plain-SHA3-384 | ecsdsa-plain-SHA3-512 ),

    String certifiedDataType = "";
    ArrayList<ASN1Primitive> certifiedData = new ArrayList<ASN1Primitive>();
    String serialNumber = "";
    String signatureAlgorithm = "";
    ArrayList<ASN1Primitive> signatureAlgorithmParameters = new ArrayList<ASN1Primitive>();
    String logTimeType = "";
    String logTimeUTC = "";
    String logTimeGeneralizedTime = "";
    int logTimeUnixTime = 0;
    byte[] signatureValue = null;
    MyByteArrayOutputStream dtbsStream = new MyByteArrayOutputStream();
    BigInteger signatureCounter = new BigInteger("5");
    byte[] seAuditData = null;
    byte[] dtbs = null;
    String filename = "";


    public LogMessage(byte[] _content, String filename) {
        try {
            final ASN1InputStream decoder = new ASN1InputStream(_content);
            ASN1Primitive primitive = decoder.readObject();

            this.filename = filename;
            if (primitive instanceof ASN1Sequence) {
                Enumeration test = ((ASN1Sequence) primitive).getObjects();

                ASN1Primitive element = (ASN1Primitive) test.nextElement();

                //The first element has to be the version number
                if (element instanceof ASN1Integer) {
                    this.version = ((ASN1Integer) element).intValueExact();
                    byte[] elementValue = Arrays.copyOfRange(((ASN1Integer) element).getEncoded(), 2, ((ASN1Integer) element).getEncoded().length);
                    this.dtbsStream.write(elementValue);
                } else {
                    throw new BadFormatForLogMessage(String.format("Fehler beim Parsen von %s. Das version Element in der logMessage konnte nicht gefunden werden.", filename));
                }

                // Die Versionsnummer muss 2 sein
                if (this.version != 2){
                    throw new BadFormatForLogMessage(String.format("Fehler beim Parsen von %s. Die Versionsnummer ist nicht 2", filename));
                }

                element = (ASN1Primitive) test.nextElement();

                // Then, the object identifier for the certified data type shall follow
                if (element instanceof ASN1ObjectIdentifier) {
                    this.certifiedDataType = ((ASN1ObjectIdentifier) element).getId();
                    byte[] elementValue = Arrays.copyOfRange(((ASN1ObjectIdentifier) element).getEncoded(), 2, ((ASN1ObjectIdentifier) element).getEncoded().length);
                    this.dtbsStream.write(elementValue);

                } else {
                    throw new BadFormatForLogMessage(String.format("Fehler beim Parsen von %s. certifiedDataType Element wurde nicht gefunden.", filename));
                }

                // Prüfen, dass der certifiedDataType ein erlaubter Wert ist
                if (!Arrays.asList(allowedCertifiedDataType).contains(this.certifiedDataType)){
                    throw new BadFormatForLogMessage(String.format("Error while parsing %s. Der Wert von certifiedDataType ist nicht erlaubt. er lautet %s", filename, this.certifiedDataType));

                }

                // Now, we will enter a while loop and collect all the certified data
                element = (ASN1Primitive) test.nextElement();
                while (!(element instanceof ASN1OctetString)) {
                    // Then, the object identifier for the certified data type shall follow
                    this.certifiedData.add(element);
                    byte[] elementValue = Arrays.copyOfRange(((ASN1Primitive) element).getEncoded(), 2, ((ASN1Primitive) element).getEncoded().length);
                    this.dtbsStream.write(elementValue);

                    element = (ASN1Primitive) test.nextElement();
                }

                // Then, the serial number is expected
                if (element instanceof ASN1OctetString) {
                    //FIXME: I have no idea, why the first charater shows
                    this.serialNumber = ((ASN1OctetString) element).toString().toUpperCase().substring(1);
                    byte[] elementValue = Arrays.copyOfRange(((ASN1OctetString) element).getEncoded(), 2, ((ASN1OctetString) element).getEncoded().length);
                    this.dtbsStream.write(elementValue);
                } else {
                    throw new BadFormatForLogMessage(String.format("Fehler beim Parsen von %s. serialNumber wurde nicht gefunden.", filename));
                }

                // Prüfen, dass die Serial Number auch da ist.
                if (this.serialNumber == null){
                    throw new BadFormatForLogMessage(String.format("Error while parsing %s. Die Serial Number ist null", filename));
                }

                element = (ASN1Primitive) test.nextElement();
                // Then, the sequence for the signatureAlgorithm  is expected
                if (element instanceof ASN1Sequence) {

                    Enumeration sigAlgorithmEnumeration = ((ASN1Sequence) element).getObjects();

                    element = (ASN1Primitive) sigAlgorithmEnumeration.nextElement();
                    // First, we read the signatureAlgorithm itself

                    if (element instanceof ASN1ObjectIdentifier) {
                        this.signatureAlgorithm = ((ASN1ObjectIdentifier) element).toString();
                        byte[] elementValue = Arrays.copyOfRange(((ASN1ObjectIdentifier) element).getEncoded(), 2, ((ASN1ObjectIdentifier) element).getEncoded().length);
                        this.dtbsStream.write(elementValue);

                    } else {
                        throw new BadFormatForLogMessage(String.format("Fehler beim Parsen von %s. signatureAlgorithm wurde nicht gefunden.", filename));
                    }

                    if (!Arrays.asList(allowedAlgorithms).contains(this.signatureAlgorithm)){
                        throw new BadFormatForLogMessage(String.format("Error while parsing %s. Die OID für signatureAlgorithm lautet %s. Dies ist keine erlaubte OID", filename, this.signatureAlgorithm));

                    }


                    //Then, we loop over the rest of the sequence for the options
                    while (sigAlgorithmEnumeration.hasMoreElements()) {
                        element = (ASN1Primitive) sigAlgorithmEnumeration.nextElement();
                        this.signatureAlgorithmParameters.add(element);
                    }

                } else {
                    throw new BadFormatForLogMessage(String.format("Fehler beim Parsen von %s. Die Sequenz für den signatureAlgortihm wurde nicht gefunden.", filename));
                }

                element = (ASN1Primitive) test.nextElement();
                // Then, we are checking whether we have seAuditData

                if (element instanceof ASN1OctetString) {
                    this.seAuditData = ((ASN1OctetString) element).getOctets();
                    byte[] elementValue = Arrays.copyOfRange(((ASN1OctetString) element).getEncoded(), 2, ((ASN1OctetString) element).getEncoded().length);
                    this.dtbsStream.write(elementValue);
                    element = (ASN1Primitive) test.nextElement();

                } else {
                    logger.info(String.format("Information für %s. seAuditData wurde nicht gefunden.", filename));
                }

                // Then, we are checking whether we have seAuditData
                if (element instanceof ASN1Integer) {
                    this.signatureCounter = ((ASN1Integer) element).getValue();
                    byte[] elementValue = Arrays.copyOfRange(((ASN1Integer) element).getEncoded(), 2, ((ASN1Integer) element).getEncoded().length);
                    this.dtbsStream.write(elementValue);

                } else {
                    throw new BadFormatForLogMessage(String.format("Fehler beim Parsen von  %s. Der signatureCounter wurde nicht gefunden", filename));
                }

                if (signatureCounter == null){
                    throw new BadFormatForLogMessage(String.format("Fehler beim Parsen von %s . Der signatureCounter ist nicht vorhanden", filename));

                }

                element = (ASN1Primitive) test.nextElement();
                // Now, we expect the logTime as one of three typey
                if (element instanceof ASN1Integer) {
                    this.logTimeUnixTime = ((ASN1Integer) element).getValue().intValue();
                    byte[] elementValue = Arrays.copyOfRange(((ASN1Integer) element).getEncoded(), 2, ((ASN1Integer) element).getEncoded().length);
                    this.dtbsStream.write(elementValue);
                    this.logTimeType = "unixTime";
                } else if (element instanceof ASN1UTCTime) {
                    this.logTimeUTC = ((ASN1UTCTime) element).getTime();
                    byte[] elementValue = Arrays.copyOfRange(((ASN1UTCTime) element).getEncoded(), 2, ((ASN1UTCTime) element).getEncoded().length);
                    this.dtbsStream.write(elementValue);
                    this.logTimeType = "utcTime";
                } else if (element instanceof ASN1GeneralizedTime) {
                    this.logTimeGeneralizedTime = ((ASN1GeneralizedTime) element).getTime();
                    byte[] elementValue = Arrays.copyOfRange(((ASN1GeneralizedTime) element).getEncoded(), 2, ((ASN1GeneralizedTime) element).getEncoded().length);
                    this.dtbsStream.write(elementValue);
                    this.logTimeType = "generalizedTime";
                } else {
                    throw new BadFormatForLogMessage(String.format("Fehler beim Parsen von %s. logTime Element wurde nicht gefunden.", filename));
                }

                if (logTimeType == null){
                    throw new BadFormatForLogMessage(String.format("Fehler beim Parsen von %s. Es ist kein Typ für die LogZeit vorhanden", filename));
                }

                element = (ASN1Primitive) test.nextElement();

                // Now, the last element shall be the signature
                if (element instanceof ASN1OctetString) {
                    byte[] elementValue = Arrays.copyOfRange(((ASN1OctetString) element).getEncoded(), 2, ((ASN1OctetString) element).getEncoded().length);
                    this.signatureValue = elementValue;
                } else {
                    throw new BadFormatForLogMessage(String.format("Fehler beim Parsen von %s. signature wurde nicht gefunden.", filename));
                }

                this.dtbs = this.dtbsStream.toByteArray();
            }

        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
    }

    /**
     * @return die toString Methode wurde überschrieben. Sie gibt den Dateinamen zurück, aus dem die LogMessage stammt
     */
    public String toString() {
        return this.filename;
    }

    /**
     * @return Diese Funktion gibt eine gut lesbare Zusammenfassung der Inhalte der LogMessage aus
     */
    public String prettyPrint() {
        String return_value = String.format("The following log message has been extracted from file %s", this.filename);
        return_value += System.lineSeparator();
        return_value += String.format("version: %d", this.version);
        return_value += System.lineSeparator();
        return_value += String.format("certifiedDataType: %s", this.certifiedDataType);
        return_value += System.lineSeparator();

        for (int i = 0; i < this.certifiedData.size(); i++) {
            return_value += String.format("certifiedData: %s", this.certifiedData.get(i).toString());
            return_value += System.lineSeparator();
        }

        return_value += String.format("serialNumber: %s", this.serialNumber);
        return_value += System.lineSeparator();
        return_value += String.format("signatureAlgorithm: %s", this.signatureAlgorithm);
        return_value += System.lineSeparator();

        for (int i = 0; i < this.signatureAlgorithmParameters.size(); i++) {
            return_value += String.format("certifiedData: %s", this.signatureAlgorithmParameters.get(i).toString());
            return_value += System.lineSeparator();
        }
        if (this.seAuditData != null) {
            return_value += String.format("seAuditData: %s", this.seAuditData.toString());
            return_value += System.lineSeparator();
        }

        return_value += String.format("signatureCounter: %d", this.signatureCounter);
        return_value += System.lineSeparator();

        return_value += String.format("logTimeFormat:: %s", this.logTimeType);
        return_value += System.lineSeparator();

        switch (this.logTimeType){
            case "unixTime":
                return_value += String.format("logTime: %d", this.logTimeUnixTime);
                return_value += System.lineSeparator();
                break;
            case "utcTime":
                return_value += String.format("logTime: %d", this.logTimeUTC.toString());
                return_value += System.lineSeparator();
                break;
            case "generalizedTime":
                return_value += String.format("logTime: %d", this.logTimeGeneralizedTime.toString());
                return_value += System.lineSeparator();
                break;
        }

        return_value += String.format("signatureValue:: %s", Hex.encodeHexString(this.signatureValue));
        return_value += System.lineSeparator();

        return_value += String.format("dtbs:: %s", Hex.encodeHexString(this.dtbs));
        return_value += System.lineSeparator();

        return(return_value);
    }

}


