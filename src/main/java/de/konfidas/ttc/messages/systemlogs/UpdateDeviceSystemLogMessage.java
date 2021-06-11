package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.utilities.DLTaggedObjectConverter;
import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;


/**
 * Diese Klasse repräsentiert eine authenticateUserSystemLog Message. Dabei werden in der Methode
 * parseSystemOperationDataContent die folgenden Elemente aus systemOperationData geparst
 * <pre>
 * ╔═══════════════════════╤══════╤═══════════════════════════════════════════════════════════════╤════════════╗
 * ║ Data field            │ Tag  │ Data Type                                                     │ Mandatory? ║
 * ╠═══════════════════════╪══════╪═══════════════════════════════════════════════════════════════╪════════════╣
 * ║ userID                │ 0x81 │ PrintableString                                               │ m          ║
 * ╟───────────────────────┼──────┼───────────────────────────────────────────────────────────────┼────────────╢
 * ║ oldVersion            │ 0x84 │ OCTECTSTRING                                                  │ m          ║
 * ╚═══════════════════════╧══════╧══════════════════════════════════╧═════════════════════════════════════════╝
 * </pre>
 */
public class UpdateDeviceSystemLogMessage extends SystemLogMessage {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    static Locale locale = new Locale("de", "DE"); //NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS

    public DLTaggedObject getUserId() {
        return userId;
    }

    public void setUserId(DLTaggedObject userId) {
        this.userId = userId;
    }

    public DLTaggedObject getOldVersion() {
        return oldVersion;
    }

    public void setOldVersion(DLTaggedObject oldVersion) {
        this.oldVersion = oldVersion;
    }

    public String getUserIDAsString() {
        return userIDAsString;
    }

    public void setUserIDAsString(String userIDAsString) {
        this.userIDAsString = userIDAsString;
    }

    public String getOldVersionComponentName() {
        return oldVersionComponentName;
    }

    public void setOldVersionComponentName(String oldVersionComponentName) {
        this.oldVersionComponentName = oldVersionComponentName;
    }

    public String getOldVersionManufacturer() {
        return oldVersionManufacturer;
    }

    public void setOldVersionManufacturer(String oldVersionManufacturer) {
        this.oldVersionManufacturer = oldVersionManufacturer;
    }

    public String getOldVersionModel() {
        return oldVersionModel;
    }

    public void setOldVersionModel(String oldVersionModel) {
        this.oldVersionModel = oldVersionModel;
    }

    public String getOldVersionVersion() {
        return oldVersionVersion;
    }

    public void setOldVersionVersion(String oldVersionVersion) {
        this.oldVersionVersion = oldVersionVersion;
    }

    public String getOldVersionCertificationID() {
        return oldVersionCertificationID;
    }

    public void setOldVersionCertificationID(String oldVersionCertificationID) {
        this.oldVersionCertificationID = oldVersionCertificationID;
    }

    DLTaggedObject userId;
    DLTaggedObject oldVersion;


    String userIDAsString;
    String oldVersionComponentName;
    String oldVersionManufacturer;
    String oldVersionModel;
    String oldVersionVersion;
    String oldVersionCertificationID;



    public UpdateDeviceSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }


    @Override
        protected void parseSystemOperationDataContent(ASN1InputStream stream) throws SystemLogParsingException, IOException {

        ASN1Primitive systemOperationData = stream.readObject();
        if (!(systemOperationData instanceof ASN1Sequence)) throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataContent"));

        List<ASN1Primitive> systemOperationDataAsAsn1List = Collections.list(((ASN1Sequence) systemOperationData).getObjects());
        ListIterator<ASN1Primitive> systemOperationDataIterator = systemOperationDataAsAsn1List.listIterator();

        try {
            //userID einlesen
            DLTaggedObject nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 1) throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataContentUserIDNotFound"));

            this.userId = (DLTaggedObject) systemOperationDataIterator.next();
            this.userIDAsString = DLTaggedObjectConverter.dLTaggedObjectToString(this.userId);

            //oldVersion einlesen
             nextElement = (DLTaggedObject) systemOperationDataAsAsn1List.get(systemOperationDataIterator.nextIndex());
            if (nextElement.getTagNo() != 3) throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataContentOldVersionNotFound"));

            this.oldVersion = (DLTaggedObject) systemOperationDataIterator.next();

            //oldVersion is a Sequence in itself. Parsing follows

            if (this.oldVersion.getObject() instanceof ASN1Sequence) {

                List<ASN1Primitive> deviceInformationSetAsASN1List = Collections.list(((ASN1Sequence) this.oldVersion.getObject()).getObjects());
                ListIterator<ASN1Primitive> deviceInformationSetIterator = deviceInformationSetAsASN1List.listIterator();

                if (!deviceInformationSetIterator.hasNext()) { throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorDeviceInformationSetOfUpdateTimeEndedEarly")); }

                List<ASN1Primitive> componentInformationSetAsASN1 = Collections.list(((ASN1Sequence) deviceInformationSetAsASN1List.get(deviceInformationSetIterator.nextIndex())).getObjects());
                ListIterator<ASN1Primitive> componentInformationSetItertator = componentInformationSetAsASN1.listIterator();

                //component Name
                if (!deviceInformationSetIterator.hasNext()) { throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorComponentInformationSetOfUpdateTimeEndedEarly")); }
                ASN1Primitive element = deviceInformationSetIterator.next();
                this.oldVersionComponentName = ((ASN1String) element).getString();

                //manufacturer
                if (!deviceInformationSetIterator.hasNext()) { throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorComponentInformationSetOfUpdateTimeEndedEarly")); }
                element = deviceInformationSetIterator.next();
                this.oldVersionManufacturer = ((ASN1String) element).getString();

                //model
                if (!deviceInformationSetIterator.hasNext()) { throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorComponentInformationSetOfUpdateTimeEndedEarly")); }
                element = deviceInformationSetIterator.next();
                this.oldVersionModel = ((ASN1String) element).getString();

                //version
                if (!deviceInformationSetIterator.hasNext()) { throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorComponentInformationSetOfUpdateTimeEndedEarly")); }
                element = deviceInformationSetIterator.next();
                this.oldVersionVersion = ((ASN1String) element).getString();                //version

                if (deviceInformationSetIterator.hasNext()) {
                element = deviceInformationSetIterator.next();
                this.oldVersionCertificationID = ((ASN1String) element).getString();
                }

            }
            else throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorOldVersionDoesNotStartWithSequence"));


        }
        catch (NoSuchElementException ex){
            throw new SystemLogParsingException(properties.getString("de.konfidas.ttc.messages.systemlogs.errorEarlyEndOfSystemOperationData"), ex);
        }
    }


}