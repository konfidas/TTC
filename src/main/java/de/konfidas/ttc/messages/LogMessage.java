package de.konfidas.ttc.messages;

import de.konfidas.ttc.utilities.ByteArrayOutputStream;
import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.utilities.oid;
import org.apache.commons.codec.binary.BinaryCodec;
import org.bouncycastle.asn1.*;

import java.io.File;
import java.io.IOException;
import java.math.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.*;

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
public abstract class LogMessage {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    String[] allowedCertifiedDataType = {"0.4.0.127.0.7.3.7.1.1", "0.4.0.127.0.7.3.7.1.2", "0.4.0.127.0.7.3.7.1.3"};
    String[] allowedAlgorithms = {"0.4.0.127.0.7.1.1.4.1.2", "0.4.0.127.0.7.1.1.4.1.3", "0.4.0.127.0.7.1.1.4.1.4", "0.4.0.127.0.7.1.1.4.1.5","0.4.0.127.0.7.1.1.4.1.8", "0.4.0.127.0.7.1.1.4.1.9", "0.4.0.127.0.7.1.1.4.1.10", "0.4.0.127.0.7.1.1.4.1.11","0.4.0.127.0.7.1.1.4.4.1", "0.4.0.127.0.7.1.1.4.4.2", "0.4.0.127.0.7.1.1.4.4.3", "0.4.0.127.0.7.1.1.4.4.4", "0.4.0.127.0.7.1.1.4.4.5", "0.4.0.127.0.7.1.1.4.4.6", "0.4.0.127.0.7.1.1.4.4.7", "0.4.0.127.0.7.1.1.4.4.8" };

    int version = 0;
    oid certifiedDataType;
    ArrayList<ASN1Primitive> certifiedData = new ArrayList<>();
    byte[] serialNumber;
    String signatureAlgorithm = "";
    ArrayList<ASN1Primitive> signatureAlgorithmParameters = new ArrayList<>();
    String logTimeType = "";
    String logTimeUTC = "";
    String logTimeGeneralizedTime = "";
    int logTimeUnixTime = 0;
    byte[] signatureValue = null;
    BigInteger signatureCounter = new BigInteger("5");
    byte[] seAuditData = null;
    byte[] dtbs = null;
    String filename = "";


    public LogMessage(File file) throws IOException, BadFormatForLogMessageException {
        this(Files.readAllBytes(file.toPath()), file.getName());
    }

    public LogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        this.filename = filename;
        parse(content);
        checkContent();
    }

    /**
     * @return die toString Methode wurde überschrieben. Sie gibt den Dateinamen zurück, aus dem die LogMessage stammt
     */
    public String toString() {
        return this.filename;
    }

    public byte[] getSerialNumber(){
        return this.serialNumber;
    }

    public String getFileName(){
        return this.filename;
    }

    public byte[] getSignatureValue() {
        return this.signatureValue;
    }

    public byte[] getDTBS() {
        return this.dtbs;
    }

    public String getSignatureAlgorithm(){
        return this.signatureAlgorithm;
    }

    public int getLogTimeUnixTime() { return logTimeUnixTime; }

    public BigInteger getSignatureCounter(){ return signatureCounter; }

    /**
     * Diese Funktion gibt die Lönge eines ASN1Elements als integer zurück.
     * Falls die Länge nicht in ein Integer oasst, wird ein Fehler geworfen
     * Bei indefinite lgenght encoding wir 0 zurückgegeben
     * @param element
     * @return Gibt die Länge des Elements als integer zurück
     * @throws IOException
     * @throws ExtendLengthValueExceedsInteger Wird geworfen, falls element mit einer extended length kodiert ist, die mehr als 4 bytes erfordert
     */
    private int getEncodedLength(ASN1Primitive element) throws IOException, ExtendLengthValueExceedsInteger{
        byte[] elementContent = element.getEncoded();

        if ((byte)elementContent[1] == (byte)0b10000000) {
            //indefinte length encoding
            return 0;
        }

        else if ((elementContent[1] & 0b10000000) == 0){
            //Case: Definite length encocding, one byte
            return Integer.valueOf(elementContent[1]);
        }

        else {
            //Extended length encoding (limitiert auf max 4 bytes für die Länge)
            int elementNumberOfLengthBytes = (elementContent[1] & 0b01111111);
            if (elementNumberOfLengthBytes>4){ throw new ExtendLengthValueExceedsInteger("Der Wert der extended length überschreitet einen Integer",null); }
            byte[] lengthBytes = Arrays.copyOfRange(elementContent, 1,elementNumberOfLengthBytes+1);
            return ByteBuffer.wrap(lengthBytes).getInt();
        }

    }

    byte[] getEncodedValue(ASN1Primitive element) throws IOException, ExtendLengthValueExceedsInteger {
        byte [] elementContent = element.getEncoded();
        int elementLength = this.getEncodedLength(element);
        return Arrays.copyOfRange(elementContent, elementContent.length - elementLength, elementContent.length+1);
    }

    void parse(byte[] content) throws LogMessageParsingException{
        try (ByteArrayOutputStream dtbsStream = new ByteArrayOutputStream()) {
            final ASN1InputStream inputStreamDecoder = new ASN1InputStream(content);
            ASN1Primitive logMessageAsASN1 = inputStreamDecoder.readObject();


            if (logMessageAsASN1 instanceof ASN1Sequence) {

                List<ASN1Primitive> logMessageAsASN1List = Collections.list(((ASN1Sequence) logMessageAsASN1).getObjects());
                ListIterator<ASN1Primitive> logMessageIterator = logMessageAsASN1List.listIterator();


//                ASN1Primitive element = logMessageElementsAsASN1.nextElement();

                //Das erste Element MUSS die versionNumber sein
                parseVersionNumber(dtbsStream,logMessageAsASN1List, logMessageIterator);
                parseCertifiedDataType(dtbsStream,logMessageAsASN1List, logMessageIterator);



                if (inputStreamDecoder.readObject() instanceof ASN1ObjectIdentifier) {
                    element = parseCertifiedData(dtbsStream, logMessageIterator); // TODO: CertifiedData ends with optional element. So parseCertifiedData fetches one element to much.
                    //FIXME: Dieser Teil des Parsers ist tricky. Wir gehen aktuell davon aus, dass wenn certifiedDataType gesetzt ist, dass dann auch certifiedData vorhanden ist. Aber hier gibt es einige
                    //theoretische Fälle, die Probleme machen können.
                }
                else {
                    throw new LogMessageParsingException("certifiedDataType konnte nicht gefunden werden.");
                }

                parseSerialNumber(dtbsStream,element);

                element = logMessageIterator.nextElement();
                // Dann wir die Sqequenz für den signatureAlgorithm erwartet
                if (element instanceof ASN1Sequence) {

                    Enumeration<ASN1Primitive> sigAlgorithmEnumeration = ((ASN1Sequence) element).getObjects();

                    element = sigAlgorithmEnumeration.nextElement();
                    // Erst lesen wir den signatureAlgorihtm selbst

                    if (element instanceof ASN1ObjectIdentifier) {
                        this.signatureAlgorithm = element.toString();
                        dtbsStream.write(this.getEncodedValue(element));

                    }
                    else {
                        throw new LogMessageParsingException("signatureAlgorithm wurde nicht gefunden.");
                    }

                    if (!Arrays.asList(allowedAlgorithms).contains(this.signatureAlgorithm)) {
                        throw new LogMessageParsingException(String.format("Die OID für signatureAlgorithm lautet %s. Dies ist keine erlaubte OID", this.signatureAlgorithm));
                    }


                    //Dann eine Schleife über den Rest für die SignatureAlgorithmParameters
                    while (sigAlgorithmEnumeration.hasMoreElements()) {
                        element = sigAlgorithmEnumeration.nextElement();
                        this.signatureAlgorithmParameters.add(element);
                    }

                }
                else {
                    throw new LogMessageParsingException("Die Sequenz für den signatureAlgortihm wurde nicht gefunden.");
                }

                element = logMessageIterator.nextElement();
                // Dann prüfen wir, ob wir seAuditData finden

                if (element instanceof ASN1OctetString) {
                    this.seAuditData = ((ASN1OctetString) element).getOctets();
                    dtbsStream.write(this.getEncodedValue(element));
                    element = logMessageIterator.nextElement();

                } else {
                    logger.debug(String.format("Information für %s. seAuditData wurde nicht gefunden.", filename));
                }

                // Dann prüfen wir, ob wir einen signatureCounter finden
                if(! logMessageIterator.hasMoreElements()){
                    throw new LogMessageParsingException("No More Elements, signature missing!");
                }
                ASN1Primitive nextElement = logMessageIterator.nextElement();

                boolean hasSignatureCounter = false;
                // Prüfe, ob nextElement logTime ist. Falls nicht, ist das aktuelle Element logTime. In diesem Fall ist kein signatureCoutner vorhandem
                if(nextElement instanceof  ASN1Integer || nextElement instanceof ASN1UTCTime || nextElement instanceof ASN1GeneralizedTime) {
                    hasSignatureCounter = true;
                    parseSignatureCounter(dtbsStream, element);
                }

                if(hasSignatureCounter){
                    parseTime(dtbsStream, nextElement);
                    element = logMessageIterator.nextElement();
                }else {
                    parseTime(dtbsStream, element);
                    element = nextElement;
                }

                // Das letzte Element is die Signatur
                if (element instanceof ASN1OctetString) {
                    this.signatureValue = Arrays.copyOfRange(element.getEncoded(), 2, element.getEncoded().length);
                }
                else {
                    throw new LogMessageParsingException("signature wurde nicht gefunden.");
                }

                //Speichern des DTBS aus dem BufferedWriter
                this.dtbs = dtbsStream.toByteArray();
            }
        }catch(IOException | NoSuchElementException e){
            throw new LogMessageParsingException("failed to parse log message",e);
        }
    }

    private void parseVersionNumber(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()){ throw new LogMessageParsingException("Version element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1Integer)){ throw new LogMessageParsingException("vesrion has to be ASN1Integer, but is " + nextElement.getClass()); }

        ASN1Primitive element = logMessageIterator.next();
        this.version = ((ASN1Integer) element).intValueExact();
        dtbsStream.write(this.getEncodedValue(element));
    }

    private void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, List<ASN1Primitive> logMessageAsASN1List, ListIterator<ASN1Primitive> logMessageIterator) throws LogMessageParsingException, IOException {
        if (!logMessageIterator.hasNext()){ throw new LogMessageParsingException("certifidData element not found"); }
        ASN1Primitive nextElement = logMessageAsASN1List.get(logMessageIterator.nextIndex());
        if (!(nextElement instanceof ASN1ObjectIdentifier)){ throw new LogMessageParsingException("certifidData has to be ASN1ObjectIdentifier, but is " + nextElement.getClass()); }

        ASN1Primitive element = logMessageIterator.next();

        try { this.certifiedDataType = oid.fromBytes(element.getEncoded()); }
            catch (oid.UnknownOidException e) { throw new CertifiedDataTypeParsingException("OID for certifiedData unknown",e); }

        dtbsStream.write(this.getEncodedValue(element));


    }

    private void parseSignatureCounter(ByteArrayOutputStream dtbsStream, ASN1Primitive element) throws LogMessageParsingException, IOException {
        if (!(element instanceof ASN1Integer)) {
            throw new LogMessageParsingException("SignatureCounter has to be ASN1Integer, but is " + element.getClass());
        }
        this.signatureCounter = ((ASN1Integer) element).getValue();
        dtbsStream.write(this.getEncodedValue(element));

        if (signatureCounter == null) {
            throw new LogMessageParsingException("SignatureCounter is missing.");
        }
    }

    private void parseTime(ByteArrayOutputStream dtbsStream, ASN1Primitive element) throws IOException, LogMessageParsingException {
        // Wir erwarten, dass logTime einer der folgenden drei Typen ist
        if (element instanceof ASN1Integer) {
            this.logTimeUnixTime = ((ASN1Integer) element).getValue().intValue();
            dtbsStream.write(this.getEncodedValue(element));
            this.logTimeType = "unixTime";
        }
        else if (element instanceof ASN1UTCTime) {
            this.logTimeUTC = ((ASN1UTCTime) element).getTime();
            dtbsStream.write(this.getEncodedValue(element));
            this.logTimeType = "utcTime";
        }
        else if (element instanceof ASN1GeneralizedTime) {
            this.logTimeGeneralizedTime = ((ASN1GeneralizedTime) element).getTime();
            dtbsStream.write(this.getEncodedValue(element));
            this.logTimeType = "generalizedTime";
        }
        else {
            throw new LogMessageParsingException("logTime Element wurde nicht gefunden.");
        }
    }

    private void parseSerialNumber(ByteArrayOutputStream dtbsStream,ASN1Primitive element) throws IOException, SerialNumberParsingException {
        if(element == null){
            throw new SerialNumberParsingException("Failed to Parse Certified Data Type, no more elements in ASN1 Object", null);
        }

        if (element instanceof ASN1OctetString) {
            this.serialNumber = ((ASN1OctetString) element).getOctets();
            dtbsStream.write(this.serialNumber);
        } else {
            throw new SerialNumberParsingException(String.format("Fehler beim Parsen von %s. serialNumber wurde nicht gefunden.", filename),null);
        }
    }

//    void parseCertifiedDataType(ByteArrayOutputStream dtbsStream, Enumeration<ASN1Primitive> asn1Primitives) throws IOException, CertifiedDataTypeParsingException, ExtendLengthValueExceedsInteger {
//        if(!asn1Primitives.hasMoreElements()){
//            throw new CertifiedDataTypeParsingException("Failed to Parse Certified Data Type, no more elements in ASN1 Object", null);
//        }
//        ASN1Primitive element = asn1Primitives.nextElement();
//
//        if (element instanceof ASN1ObjectIdentifier) {
//
//            try {
//                this.certifiedDataType = oid.fromBytes(element.getEncoded());
//            }
//            catch (oid.UnknownOidException e) {
//                throw new CertifiedDataTypeParsingException("OID unknown",e);
//            }
//
//            dtbsStream.write(this.getEncodedValue(element));
//        } else {
//            throw new CertifiedDataTypeParsingException(String.format("Fehler beim Parsen von %s. certifiedDataType Element wurde nicht gefunden.", filename), null);
//        }
//    }


    abstract ASN1Primitive parseCertifiedData(ByteArrayOutputStream dtbsStream, Enumeration<ASN1Primitive> test) throws IOException, LogMessageParsingException;


    void checkContent() throws LogMessageParsingException {
        // Die Versionsnummer muss 2 sein
        if (this.version != 2) {
            throw new LogMessageParsingException("Die Versionsnummer ist nicht 2");
        }

        // TODO: no longer required here. Done as part of parsing.
        // Prüfen, dass der certifiedDataType ein erlaubter Wert ist
        if (!Arrays.asList(allowedCertifiedDataType).contains(this.certifiedDataType.getReadable())) {
            throw new LogMessageParsingException(String.format("Der Wert von certifiedDataType ist nicht erlaubt. er lautet %s", this.certifiedDataType));
        }

        // Prüfen, dass die Serial Number auch da ist.
        if (this.serialNumber == null) {
            throw new LogMessageParsingException("Die Serial Number ist null");
        }

        // Und die Signatur muss auch da sein

        if (this.signatureValue == null) {
            throw new LogMessageParsingException("LogMessage ohne Signatur");
        }

        if (logTimeType == null) {
            throw new LogMessageParsingException("Es ist kein Typ für die LogZeit vorhanden");
        }
    }

    public class LogMessageParsingException extends BadFormatForLogMessageException{
        public LogMessageParsingException(String message) {
            super("Parsing Message "+filename+" failed: "+ message, null);
        }

        public LogMessageParsingException(String message, Exception reason) {
            super("Parsing Message "+filename+" failed: "+ message, reason);
        }
    }

    public class CertifiedDataTypeParsingException extends LogMessageParsingException{
        public CertifiedDataTypeParsingException(String message, Exception reason) {
            super(message, reason);
        }
    }

    public class SerialNumberParsingException extends LogMessageParsingException{
        public SerialNumberParsingException(String message, Exception reason) {
            super(message, reason);
        }
    }

    public class ExtendLengthValueExceedsInteger extends LogMessageParsingException{
        public ExtendLengthValueExceedsInteger(String message, Exception reason) {
            super(message, reason);
        }
    }
}


