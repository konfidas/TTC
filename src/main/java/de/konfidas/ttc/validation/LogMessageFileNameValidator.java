package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.LogMessageValidationException;
import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.logtime.GeneralizedLogTime;
import de.konfidas.ttc.messages.logtime.LogTime;
import de.konfidas.ttc.messages.logtime.UnixLogTime;
import de.konfidas.ttc.messages.logtime.UtcLogTime;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1UTCTime;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Collection;
import java.util.LinkedList;


// This class implements the checks, which were requested in https://github.com/konfidas/TTC/issues/7

/**
 * BSI-TR03151 specifies the filenames of log messages in exported TARs. This Validator validates, the filenames
 * according to the specification.
 *
 * Section 5.1.2.1 on Page 56 specifies for transaction logs:
 *
 * DATE-FORMAT_DATE_Sig-SIGNATURE-COUNTER_LOG_No-TRANSACTION_TYPE_Client-CLIENT-ID_Fc-FILE-COUNTER.log
 *
 * Section 5.1.2.2 on Page 57 specifies for system logs:
 *
 * DATE-FORMAT_DATE_Sig-SIGNATURE-COUNTER_LOG_TYPE_Fc-FILE-COUNTER.log
 *
 * and Section 5.1.2.3 on Page 59 specifies for audit logs:
 *
 * DATE-FORMAT_DATE_Sig-SIGNATURE-COUNTER_LOG_Fc-FILE-COUNTER.log
 */
// FIXME: These do not validate the optional FILE-Counter field and even ignore additional
// fields if present.     
public class LogMessageFileNameValidator extends AggregatedValidator{
    public  LogMessageFileNameValidator(){
        this.add(new TransactionLogFileNameValidator());
        this.add(new SystemLogFileNameValidator());
        this.add(new AuditLogFileNameValidator());
    }
}
