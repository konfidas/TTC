package de.konfidas.ttc.messages.logtime;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.junit.Test;

import java.text.ParseException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UtcLogTimeTests {
    @Test
    public void testEqual() throws ParseException {

        ASN1UTCTime element = new ASN1UTCTime("200421124355Z");

        UtcLogTime t1 = new UtcLogTime(element);
        UtcLogTime t2 = new UtcLogTime(element);

        assertTrue(t1.wasNotAfter(t2));
        assertTrue(t2.wasNotAfter(t1));
    }

    @Test
    public void testEqual2() throws ParseException {

        ASN1UTCTime element = new ASN1UTCTime("2004211243Z");

        UtcLogTime t1 = new UtcLogTime(element);
        UtcLogTime t2 = new UtcLogTime(element);

        assertTrue(t1.wasNotAfter(t2));
        assertTrue(t2.wasNotAfter(t1));
    }


    @Test
    public void testDifferent() throws ParseException {

        UtcLogTime t1 = new UtcLogTime(new ASN1UTCTime("200421124355Z"));
        UtcLogTime t2 = new UtcLogTime(new ASN1UTCTime("200421124455Z"));

        assertTrue(t1.wasNotAfter(t2));
        assertFalse(t2.wasNotAfter(t1));
    }

    @Test
    public void testDifferent2() throws ParseException {
        UtcLogTime t1 = new UtcLogTime(new ASN1UTCTime("200421124355Z"));
        UtcLogTime t2 = new UtcLogTime(new ASN1UTCTime("200421124356Z"));

        assertTrue(t1.wasNotAfter(t2));
        assertFalse(t2.wasNotAfter(t1));
    }

    @Test
    public void testDifferent3() throws ParseException {
        UtcLogTime t1 = new UtcLogTime(new ASN1UTCTime("2004211243Z"));
        UtcLogTime t2 = new UtcLogTime(new ASN1UTCTime("2004211244Z"));

        assertTrue(t1.wasNotAfter(t2));
        assertFalse(t2.wasNotAfter(t1));
    }


}
