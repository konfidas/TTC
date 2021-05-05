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
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;


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



    DLTaggedObject timeOfDeactivation;

    LogTime timeOfDeactivationAsLogTime;


    public DisableSecureElementSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }


    @Override
    protected void parseSystemOperationDataContent(ASN1InputStream stream) throws SystemLogParsingException, IOException {
        String typeOfTimeFromFilename = this.getFileName().substring(0, Math.min(3, this.getFileName().length()));

        ASN1Primitive systemOperationData = stream.readObject();
        if (!(systemOperationData instanceof ASN1Sequence)) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent");

        List<ASN1Primitive> systemOperationDataAsAsn1List = Collections.list(((ASN1Sequence) systemOperationData).getObjects());
        ListIterator<ASN1Primitive> systemOperationDataIterator = systemOperationDataAsAsn1List.listIterator();

        try {
            //timeOfDeactivation einlesen
            DLTaggedObject nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 1) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld timeOfDeactivation wurde nicht gefunden");

            this.timeOfDeactivation = (DLTaggedObject) systemOperationDataIterator.next();
            switch (typeOfTimeFromFilename){
                case "Gen":
                    this.timeOfDeactivationAsLogTime = new GeneralizedLogTime((ASN1GeneralizedTime) this.timeOfDeactivation.getObject());
                    break;
                case "Utc":
                    this.timeOfDeactivationAsLogTime = new UtcLogTime((ASN1UTCTime) this.timeOfDeactivation.getObject());
                    break;
                case "Uni":
                    this.timeOfDeactivationAsLogTime = new UnixLogTime((ASN1Integer) this.timeOfDeactivation.getObject());
                    break;

            }

        }
        catch (NoSuchElementException ex ){
            throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Vorzeitiges Ende von systemOperationData", ex);
        }
        catch (ParseException ex){
            throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent.", ex);
        }

    }


}