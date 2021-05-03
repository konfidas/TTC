package de.konfidas.ttc.tars;

import de.konfidas.ttc.messages.LogMessage;
import de.konfidas.ttc.messages.LogMessageImplementation;

import java.security.cert.X509Certificate;
import java.util.*;

public class AggregatedLogMessageArchive implements LogMessageArchive{
    final LinkedList<LogMessageArchive> archives = new LinkedList<>();

    ArrayList<LogMessage> sortedLogMessages;
    ArrayList<LogMessage> logMessages;
    HashMap<String, X509Certificate> clientCertificates;
    HashMap<String, X509Certificate> intermediateCertificates;

    @Override
    public Map<String, X509Certificate> getIntermediateCertificates() {
        if(null == intermediateCertificates){
            intermediateCertificates = new HashMap<>();
            archives.stream().map(c -> c.getIntermediateCertificates()).forEach(intermediateCertificates::putAll);


            // TODO: here we might have issues with different certificates having the same name or even
            // with the same certificate, having different names.
            // maybe HashMap<String, Cert> is not the right thing here and a Collection<(String, Cert)> would be better?
        }
        return intermediateCertificates;
    }

    @Override
    public Map<String, X509Certificate> getClientCertificates() {
        if(null == clientCertificates){
            clientCertificates = new HashMap<>();
            archives.stream().map(c -> c.getClientCertificates()).forEach(clientCertificates::putAll);

            // TODO: here we might have issues with different certificates having the same name or even
            // with the same certificate, having different names.
            // maybe HashMap<String, Cert> is not the right thing here and a Collection<(String, Cert)> would be better?
        }

        return clientCertificates;

    }

    @Override
    public Collection<LogMessage> getLogMessages() {
        if(null == logMessages){
            // Taking the de-tour via the HashSet removes duplicates. Note that LogMessages are equal
            // if and only if their encodings are equal!
            HashSet<LogMessage> collector = new HashSet<>();
            archives.stream().map(c -> c.getLogMessages()).forEach(collector::addAll);
            logMessages = new ArrayList<>(collector);
        }
        return logMessages;
    }

    public AggregatedLogMessageArchive addArchive(LogMessageArchive a){
        this.archives.add(a);

        // invalidate cache:
        sortedLogMessages = null;
        logMessages = null;
        clientCertificates = null;
        intermediateCertificates = null;

        return this;
    }

    @Override
    public ArrayList<LogMessage> getSortedLogMessages(){
        if(null == sortedLogMessages){
            sortedLogMessages = new ArrayList<>(getLogMessages());
            sortedLogMessages.sort(new LogMessageImplementation.SignatureCounterComparator());
        }

        return sortedLogMessages;
    }
}
