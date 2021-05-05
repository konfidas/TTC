package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.messages.logtime.GeneralizedLogTime;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.messages.logtime.UnixLogTime;
import de.konfidas.ttc.messages.logtime.UtcLogTime;
import de.konfidas.ttc.utilities.DLTaggedObjectConverter;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;


/**
 * Diese Klasse repräsentiert eine updateTimeSystemLog Message. Dabei werden in der Methode
 * parseSystemOperationDataContent die folgenden Elemente aus systemOperationData geparst
 * <pre>
 * ╔═══════════════════════╤══════╤═══════════════════════════════════════════════════════════════╤════════════╗
 * ║ Data field            │ Tag  │ Data Type                                                     │ Mandatory? ║
 * ╠═══════════════════════╪══════╪═══════════════════════════════════════════════════════════════╪════════════╣
 * ║ timeBeforeUpdate      │ 0x81 │ Time                                                          │ m          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ timeAfterUpdate       │ 0x82 │ Time                                                          │ m          ║
 * ╚═══════════════════════╧══════╧════════════════════════════════════════════════════════════════════════════╝
 * </pre>
 */
public class UpdateTimeSystemLogMessage extends SystemLogMessage {

    public DLTaggedObject getTimeBeforeUpdate() {
        return timeBeforeUpdate;
    }

    public void setTimeBeforeUpdate(DLTaggedObject timeBeforeUpdate) {
        this.timeBeforeUpdate = timeBeforeUpdate;
    }

    public DLTaggedObject getTimeAfterUpdate() {
        return timeAfterUpdate;
    }

    public void setTimeAfterUpdate(DLTaggedObject timeAfterUpdate) {
        this.timeAfterUpdate = timeAfterUpdate;
    }

    public LogTime getTimeBeforeUpdateAsLogTime() {
        return timeBeforeUpdateAsLogTime;
    }

    public void setTimeBeforeUpdateAsLogTime(LogTime timeBeforeUpdateAsLogTime) {
        this.timeBeforeUpdateAsLogTime = timeBeforeUpdateAsLogTime;
    }

    public LogTime getTimeAfterUpdateAsLogTime() {
        return timeAfterUpdateAsLogTime;
    }

    public void setTimeAfterUpdateAsLogTime(LogTime timeAfterUpdateAsLogTime) {
        this.timeAfterUpdateAsLogTime = timeAfterUpdateAsLogTime;
    }

    DLTaggedObject timeBeforeUpdate;
    DLTaggedObject timeAfterUpdate;

    LogTime timeBeforeUpdateAsLogTime;
    LogTime timeAfterUpdateAsLogTime;


    public UpdateTimeSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
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
            //timeBeforeUpdate einlesen
            DLTaggedObject nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 1) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld timeBeforeUpdate wurde nicht gefunden");

            this.timeBeforeUpdate = (DLTaggedObject) systemOperationDataIterator.next();
            switch (typeOfTimeFromFilename){
                case "Gen":
                    this.timeBeforeUpdateAsLogTime = new GeneralizedLogTime((ASN1GeneralizedTime) this.timeBeforeUpdate.getObject());
                    break;
                case "Utc":
                    this.timeBeforeUpdateAsLogTime = new UtcLogTime((ASN1UTCTime) this.timeBeforeUpdate.getObject());
                    break;
                case "Uni":
                    this.timeBeforeUpdateAsLogTime = new UnixLogTime((ASN1Integer) this.timeBeforeUpdate.getObject());
                    break;

            }

            //timeAfterUpdate einlesen
            nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 2) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld timeAfterUpdate wurde nicht gefunden");

            this.timeAfterUpdate = (DLTaggedObject) systemOperationDataIterator.next();
            switch (typeOfTimeFromFilename){
                case "Gen":
                    this.timeAfterUpdateAsLogTime = new GeneralizedLogTime((ASN1GeneralizedTime) this.timeAfterUpdate.getObject());
                    break;
                case "Utc":
                    this.timeAfterUpdateAsLogTime = new UtcLogTime((ASN1UTCTime) this.timeAfterUpdate.getObject());
                    break;
                case "Uni":
                    this.timeAfterUpdateAsLogTime = new UnixLogTime((ASN1Integer) this.timeAfterUpdate.getObject());
                    break;

        }}
        catch (NoSuchElementException ex ){
            throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Vorzeitiges Ende von systemOperationData", ex);
        }
        catch (ParseException ex){
            throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent.", ex);
        }

    }


}