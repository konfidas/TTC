package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.messages.logtime.GeneralizedLogTime;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.messages.logtime.UnixLogTime;
import de.konfidas.ttc.messages.logtime.UtcLogTime;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.text.ParseException;
import java.util.*;


/**
 * Diese Klasse repräsentiert eine disableSecureElementSystemLog Message. Dabei werden in der Methode
 * parseSystemOperationDataContent die folgenden Elemente aus systemOperationData geparst
 * <pre>
 * ╔═══════════════════════╤══════╤═══════════════════════════════════════════════════════════════╤════════════╗
 * ║ Data field            │ Tag  │ Data Type                                                     │ Mandatory? ║
 * ╠═══════════════════════╪══════╪═══════════════════════════════════════════════════════════════╪════════════╣
 * ║ timeOfDeactivation    │ 0x81 │ Time                                                          │ m          ║
 * ╚═══════════════════════╧══════╧════════════════════════════════════════════════════════════════════════════╝
 * </pre>
 */
public class DisableSecureElementSystemLogMessage extends SystemLogMessage {


    static Locale locale = new Locale("de", "DE");//NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS


    DLTaggedObject timeOfDeactivation;

    LogTime timeOfDeactivationAsLogTime;


    public DisableSecureElementSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }


    @Override
    protected void parseSystemOperationDataContent(ASN1InputStream stream) throws SystemLogParsingException, IOException {
        String typeOfTimeFromFilename = this.getFileName().substring(0, Math.min(3, this.getFileName().length()));

        ASN1Primitive systemOperationData = stream.readObject();
        if (!(systemOperationData instanceof ASN1Sequence)) throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataContent"));

        List<ASN1Primitive> systemOperationDataAsAsn1List = Collections.list(((ASN1Sequence) systemOperationData).getObjects());
        ListIterator<ASN1Primitive> systemOperationDataIterator = systemOperationDataAsAsn1List.listIterator();

        try {
            //timeOfDeactivation einlesen
            DLTaggedObject nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 1) throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorTimeOfDeactivationNotFound"));

            this.timeOfDeactivation = (DLTaggedObject) systemOperationDataIterator.next();
            switch (typeOfTimeFromFilename){
                case "Gen"://NON-NLS
                    this.timeOfDeactivationAsLogTime = new GeneralizedLogTime((ASN1GeneralizedTime) this.timeOfDeactivation.getObject());
                    break;
                case "Utc"://NON-NLS
                    this.timeOfDeactivationAsLogTime = new UtcLogTime((ASN1UTCTime) this.timeOfDeactivation.getObject());
                    break;
                case "Uni"://NON-NLS
                    this.timeOfDeactivationAsLogTime = new UnixLogTime((ASN1Integer) this.timeOfDeactivation.getObject());
                    break;

            }

        }
        catch (NoSuchElementException ex ){
            throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.earlyEndOfSystemOperationData"), ex);
        }
        catch (ParseException ex){
            throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataContent"), ex);

        }

    }


}