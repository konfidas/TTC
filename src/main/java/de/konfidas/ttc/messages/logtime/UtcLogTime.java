package de.konfidas.ttc.messages.logtime;

import org.bouncycastle.asn1.ASN1UTCTime;

import java.text.ParseException;
import java.util.Calendar;

public class UtcLogTime extends LogTime{
    final long time;
    final ASN1UTCTime element;

    // FIXME: I am currently unsure, where to take this offset into account!
    final static long offset =  Calendar.getInstance().get(Calendar.DST_OFFSET) + Calendar.getInstance().get(Calendar.ZONE_OFFSET);

    public UtcLogTime(ASN1UTCTime element) throws ParseException {
        this.element = element;
        this.time = element.getDate().getTime() - offset;
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
