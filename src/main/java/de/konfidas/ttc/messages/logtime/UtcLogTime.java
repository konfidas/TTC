package de.konfidas.ttc.messages.logtime;

import org.bouncycastle.asn1.ASN1UTCTime;

import java.text.ParseException;

public class UtcLogTime extends LogTime{
    long time;
    ASN1UTCTime element;

    public UtcLogTime(ASN1UTCTime element) throws ParseException {
        this.element = element;
        this.time = element.getDate().getTime();
    }

    @Override
    public String toString(){
        return element.getTime();
    }

    @Override
    public long getTime() {
        return time;
    }

    @Override
    public Type getType() {
        return Type.UTC;
    }

  }
