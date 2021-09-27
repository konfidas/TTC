package de.konfidas.ttc.tars;

import de.konfidas.ttc.errors.TtcError;
import de.konfidas.ttc.messages.LogMessage;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public interface LogMessageArchive {
    Map<? extends String, ? extends X509Certificate> getIntermediateCertificates();
    Map<? extends String, ? extends X509Certificate> getClientCertificates();
    Collection<? extends LogMessage> getLogMessages();
    String getFileName();
    ArrayList<TtcError> getAllErrors();
//            ll_errors = new ArrayList<TtcError>();


    /**
     * A lazy getter, returning the Collection of LogMessages in a sorted manner. The messages are sorted
     * with increasing signature counter. Note that this is non-deterministic, because the order of log messages
     * with the same signature counter is not prescribed. The same signature counter can occur in a valid LogMessageArchive multiple
     * times for different serial numbers.
     * @return a collection of all Log Messages of the Archive, sorted by increasing Signature Counter.
     */
    Collection<? extends LogMessage> getSortedLogMessages();
}
