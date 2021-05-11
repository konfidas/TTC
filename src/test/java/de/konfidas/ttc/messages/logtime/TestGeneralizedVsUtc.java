package de.konfidas.ttc.messages.logtime;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.junit.Test;

import java.text.ParseException;

import static org.junit.Assert.assertTrue;

public class TestGeneralizedVsUtc {


    @Test
    public void test() throws ParseException {
        LogTime a = new UtcLogTime(new ASN1UTCTime("181109084236Z"));
        LogTime b = new GeneralizedLogTime(new ASN1GeneralizedTime("20181109084236Z"));

        assertTrue(a.equals(b));
    }
}

