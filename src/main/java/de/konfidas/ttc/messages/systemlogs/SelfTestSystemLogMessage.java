package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.messages.logtime.GeneralizedLogTime;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.messages.logtime.UnixLogTime;
import de.konfidas.ttc.messages.logtime.UtcLogTime;
import de.konfidas.ttc.utilities.DLTaggedObjectConverter;
import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;


/**
 * Diese Klasse repräsentiert eine selfTest System Log Message. Dabei werden in der Methode
 * parseSystemOperationDataContent die folgenden Elemente aus systemOperationData geparst
 * <pre>
 * ╔═══════════════════════╤══════╤═══════════════════════════════════════════════════════════════╤════════════╗
 * ║ Data field            │ Tag  │ Data Type                                                     │ Mandatory? ║
 * ╠═══════════════════════╪══════╪═══════════════════════════════════════════════════════════════╪════════════╣
 * ║ componentName         │ 0x81 │ PrintableString                                               │ m          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ result                │ 0x82 │ Boolean                                                       │ m          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ errorMessage          │ 0x83 │ PrintableString                                               │ c          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ timeOfEvent           │ 0x84 │ Time                                                          │ c          ║
 * ╚═══════════════════════╧══════╧═══════════════════════════════════════════════════════════════╧════════════╝
 * </pre>
 */
public class SelfTestSystemLogMessage extends SystemLogMessage {
    static final Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);


    static Locale locale = new Locale("de", "DE");//NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc", locale);//NON-NLS


    DLTaggedObject componentName;
    DLTaggedObject result;
    DLTaggedObject errorMessage;
    DLTaggedObject timeOfEvent;

    String componentNameAsString;
    Boolean resultAsBoolean;
    String errorMessageAsString;
    LogTime timeOfEventAsLogTime;


    public SelfTestSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);

    }


    @Override
    protected void parseSystemOperationDataContent(ASN1InputStream stream) throws IOException {

        String typeOfTimeFromFilename = this.getFileName().substring(0, Math.min(3, this.getFileName().length()));


        ASN1Primitive systemOperationData = stream.readObject();
        if (!(systemOperationData instanceof ASN1Sequence)) {
            this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataContent")));
        }

        List<ASN1Primitive> systemOperationDataAsAsn1List = Collections.list(((ASN1Sequence) systemOperationData).getObjects());
        ListIterator<ASN1Primitive> systemOperationDataIterator = systemOperationDataAsAsn1List.listIterator();

        try {
            //componentName einlesen
            DLTaggedObject nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 1) this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorComonentNameNotFound")));

            this.componentName = (DLTaggedObject) systemOperationDataIterator.next();
            this.componentNameAsString = DLTaggedObjectConverter.dLTaggedObjectToString(this.componentName);

            //result
            nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 2) {
                this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorResultNotFound")));
            }

            this.result = (DLTaggedObject) systemOperationDataIterator.next();
            this.resultAsBoolean = DLTaggedObjectConverter.dLTaggedObjectToBoolean(this.result);


            //errorMessage
            nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() == 3) {
                this.errorMessage = (DLTaggedObject) systemOperationDataIterator.next();
                this.errorMessageAsString = DLTaggedObjectConverter.dLTaggedObjectToString(this.errorMessage);
            }

            //timeOfEvent
            nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() == 4) {
                this.timeOfEvent = (DLTaggedObject) systemOperationDataIterator.next();

                switch (typeOfTimeFromFilename){
                    case "Gen"://NON-NLS
                        this.timeOfEventAsLogTime = new GeneralizedLogTime(DLTaggedObjectConverter.dLTaggedObjectToASN1GeneralizedTime(this.timeOfEvent));
                        break;
                    case "Utc"://NON-NLS
                        this.timeOfEventAsLogTime = new UtcLogTime(DLTaggedObjectConverter.dLTaggedObjectToASN1UTCTime(this.timeOfEvent));
                        break;
                    case "Uni"://NON-NLS
                        this.timeOfEventAsLogTime = new UnixLogTime(DLTaggedObjectConverter.dLTaggedObjectToASN1Integer(this.timeOfEvent));
                        break;

                }
            }




        } catch (NoSuchElementException ex) {
            this.allErrors.add(new SystemLogParsingError(properties.getString("de.konfidas.ttc.messages.systemlogs.errorEarlyEndOfSystemOperationData"), ex));
        }

        catch (Exception ex){
            this.allErrors.add(new SystemLogParsingError("Error during parseSystemOperationDataContent of a selfTestSystemLog", ex));
        }
    }


}