package de.konfidas.ttc.tars;

import de.konfidas.ttc.messages.LogMessage;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;

public interface LogMessageArchive {
    Map<String, X509Certificate> getIntermediateCertificates();
    Map<String, X509Certificate> getClientCertificates();
    Collection<LogMessage> getLogMessages();
}
