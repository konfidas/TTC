package de.konfidas.ttc.tars;

import de.konfidas.ttc.messages.LogMessage;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;

public interface LogMessageArchive {
    Map<String, X509Certificate> getIntermediateCertificates();
    Map<String, X509Certificate> getClientCertificates();
    Collection<LogMessage> getLogMessages();

    /**
     * A lazy getter, returning the Collection of LogMessages in a sorted manner. The messages are sorted
     * with increasing signature counter. Note that this is non-deterministic, because the order of log messages
     * with the same signature counter is not prescribed. The same signature counter can occur in a valid LogMessageArchive multiple
     * times for different serial numbers.
     * @return a collection of all Log Messages of the Archive, sorted by increasing Signature Counter.
     */
    Collection<LogMessage> getSortedLogMessages();
}
