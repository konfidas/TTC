package de.konfidas.ttc.messages;

public class AuditLogMessage extends LogMessage {
    public AuditLogMessage(byte[] _content, String filename) {
        super(_content, filename);
    }
}
