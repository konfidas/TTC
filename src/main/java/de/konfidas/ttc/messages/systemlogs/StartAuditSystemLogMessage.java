package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.messages.SystemLogMessage;
import de.konfidas.ttc.utilities.DLTaggedObjectConverter;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLTaggedObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;


/**
 * Diese Klasse repräsentiert eine startAudit Message. systemOperationData Darf keine Daten enthalten

 */
public class StartAuditSystemLogMessage extends SystemLogMessage {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);


    public StartAuditSystemLogMessage(byte[] content, String filename) throws BadFormatForLogMessageException {
        super(content, filename);
    }


    @Override
        protected void parseSystemOperationDataContent(ASN1InputStream stream) throws SystemLogParsingException, IOException {

        ASN1Primitive systemOperationData = stream.readObject();
        if (systemOperationData.getEncoded().length>2)
            throw new SystemLogParsingException("Fehler beim Parsen. systemOperationDataContent enthält Daten obwohl es keine Daten enthalten darf");

    }


}