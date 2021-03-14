package de.konfidas.ttc.exceptions;
/**
 * Diese Exception zeigt ein fehlerhaftes TAR-File. Sie wird geworfen, wenn ein TAR-File nicht oder nur mit Fehlern geparst werden konnte.
 */
public class BadFormatForTARException extends TtcException{
    public BadFormatForTARException(String message, Throwable cause){
        super(message,cause);
    }
}

