package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.utilities.DLTaggedObjectConverter;
import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;


/**
 * Diese Klasse repräsentiert eine authenticateUserSystemLog Message. Dabei werden in der Methode
 * parseSystemOperationDataContent die folgenden Elemente aus systemOperationData geparst
 * <pre>
 * ╔═══════════════════════╤══════╤═══════════════════════════════════════════════════════════════╤════════════╗
 * ║ Data field            │ Tag  │ Data Type                                                     │ Mandatory? ║
 * ╠═══════════════════════╪══════╪═══════════════════════════════════════════════════════════════╪════════════╣
 * ║ updateResult          │ 0x81 │ ENMERATED                                                     │ m          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ reasonForFailure      │ 0x81 │ PrintableString                                               │ c          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ newVersion            │ 0x84 │ OCTECTSTRING                                                  │ m          ║
 * ╚═══════════════════════╧══════╧══════════════════════════════════╧═════════════════════════════════════════╝
 * </pre>
 */
public class UpdateDeviceCompletedSystemLogMessage extends SystemLogMessage {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);



    DLTaggedObject userId;
    DLTaggedObject reasonForFailure;
    DLTaggedObject oldVersion;


    String userIDAsString;
    BigInteger updateResultAsBigInteger;
    String reasonForFailureAsString;
    String newVersionComponentName;
    String newVersionManufacturer;
    String newVersionModel;
    String newVersionVersion;
    String newVersionCertificationID;



    public UpdateDeviceCompletedSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }


    @Override
        protected void parseSystemOperationDataContent(ASN1InputStream stream) throws SystemLogParsingException, IOException {

        ASN1Primitive systemOperationData = stream.readObject();
        if (!(systemOperationData instanceof ASN1Sequence)) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent");

        List<ASN1Primitive> systemOperationDataAsAsn1List = Collections.list(((ASN1Sequence) systemOperationData).getObjects());
        ListIterator<ASN1Primitive> systemOperationDataIterator = systemOperationDataAsAsn1List.listIterator();

        try {
            //userID einlesen
            DLTaggedObject nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 1) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld userID wurde nicht gefunden");

            this.userId = (DLTaggedObject) systemOperationDataIterator.next();
            this.userIDAsString = DLTaggedObjectConverter.dLTaggedObjectToString(this.userId);

            //oldVersion einlesen
             nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 3) throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld oldVersion wurde nicht gefunden");

            this.oldVersion = (DLTaggedObject) systemOperationDataIterator.next();

            //oldVersion is a Sequence in itself. Parsing follows

            if (this.oldVersion.getObject() instanceof ASN1Sequence) {

                List<ASN1Primitive> deviceInformationSetAsASN1List = Collections.list(((ASN1Sequence) this.oldVersion.getObject()).getObjects());
                ListIterator<ASN1Primitive> deviceInformationSetIterator = deviceInformationSetAsASN1List.listIterator();

                if (!deviceInformationSetIterator.hasNext()) { throw new SystemLogParsingException("DeviceInformationSet of updateTime ended early"); }

                List<ASN1Primitive> componentInformationSetAsASN1 = Collections.list(((ASN1Sequence) deviceInformationSetAsASN1List.get(deviceInformationSetIterator.nextIndex())).getObjects());
                ListIterator<ASN1Primitive> componentInformationSetItertator = componentInformationSetAsASN1.listIterator();

                //component Name
                if (!deviceInformationSetIterator.hasNext()) { throw new SystemLogParsingException("componentInformationSet of updateTime ended early"); }
                ASN1Primitive element = deviceInformationSetIterator.next();
                this.newVersionComponentName = ((ASN1String) element).getString();

                //manufacturer
                if (!deviceInformationSetIterator.hasNext()) { throw new SystemLogParsingException("componentInformationSet of updateTime ended early"); }
                element = deviceInformationSetIterator.next();
                this.newVersionManufacturer = ((ASN1String) element).getString();

                //model
                if (!deviceInformationSetIterator.hasNext()) { throw new SystemLogParsingException("componentInformationSet of updateTime ended early"); }
                element = deviceInformationSetIterator.next();
                this.newVersionModel = ((ASN1String) element).getString();

                //version
                if (!deviceInformationSetIterator.hasNext()) { throw new SystemLogParsingException("componentInformationSet of updateTime ended early"); }
                element = deviceInformationSetIterator.next();
                this.newVersionVersion = ((ASN1String) element).getString();                //version

                if (deviceInformationSetIterator.hasNext()) {
                element = deviceInformationSetIterator.next();
                this.newVersionCertificationID = ((ASN1String) element).getString();
                }

            }
            else throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Das Pflichtfeld oldVersion startet nicht mit einer Sequenz");




        }
        catch (NoSuchElementException ex){
            throw new SystemLogParsingException("Fehler beim Parsen des systemOperationDataContent. Vorzeitiges Ende von systemOperationData", ex);
        }
    }


}