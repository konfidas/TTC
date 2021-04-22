package de.konfidas.ttc.messages.logtime;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.security.Security;
import java.text.ParseException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LogTimeTests {

    static SecureRandom rnd;


    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
        rnd = new SecureRandom();
    }


    @Test
    public void testEqualUnixTimes(){
        int time =  rnd.nextInt();

        UnixLogTime t1 = new UnixLogTime(time);
        UnixLogTime t2 = new UnixLogTime(time);

        assertTrue(t1.wasNotAfter(t2));
        assertTrue(t2.wasNotAfter(t1));
    }

    @Test
     public void testUnixTimesOffByOne(){
        int time =  rnd.nextInt();

        UnixLogTime t1 = new UnixLogTime(time);
        UnixLogTime t2 = new UnixLogTime(time+1);

        assertTrue(t1.wasNotAfter(t2));
        assertFalse(t2.wasNotAfter(t1));
    }


    @Test
    public void testEqualGeneralizedTime() throws ParseException {

        ASN1GeneralizedTime element = new ASN1GeneralizedTime("20200421124355Z");

        GeneralizedLogTime t1 = new GeneralizedLogTime(element);
        GeneralizedLogTime t2 = new GeneralizedLogTime(element);

        assertTrue(t1.wasNotAfter(t2));
        assertTrue(t2.wasNotAfter(t1));
    }

    @Test
    public void testEqualGeneralizedTime2() throws ParseException {
        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124355Z"));
        GeneralizedLogTime t2 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124355+0000"));

        assertTrue(t1.wasNotAfter(t2));
        assertTrue(t2.wasNotAfter(t1));
    }

    @Test
    public void testEqualGeneralizedTime3() throws ParseException {
        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124355Z"));
        GeneralizedLogTime t2 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124355-0000"));

        assertTrue(t1.wasNotAfter(t2));
        assertTrue(t2.wasNotAfter(t1));
    }

    @Test
    public void testEqualGeneralizedTime4() throws ParseException {
        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124355Z"));
        GeneralizedLogTime t2 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124455+0001"));

        assertTrue(t1.wasNotAfter(t2));
        assertTrue(t2.wasNotAfter(t1));
    }

    @Test
    public void testEqualGeneralizedTime4b() throws ParseException {
        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421125955Z"));
        GeneralizedLogTime t2 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421130055+0001"));

        assertTrue(t1.wasNotAfter(t2));
        assertTrue(t2.wasNotAfter(t1));
    }


    @Test
    public void testEqualGeneralizedTime5() throws ParseException {
        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124355Z"));
        GeneralizedLogTime t2 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421114355-0100"));

        assertTrue(t1.wasNotAfter(t2));
        assertTrue(t2.wasNotAfter(t1));
    }

    @Test
    public void testEqualGeneralizedTime6() throws ParseException {
        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124355Z"));
        GeneralizedLogTime t2 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421134355+0100"));

        assertTrue(t1.wasNotAfter(t2));
        assertTrue(t2.wasNotAfter(t1));
    }

    @Test
    public void testNotEqualGeneralizedTime() throws ParseException {
        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124355Z"));
        GeneralizedLogTime t2 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124356Z"));


        assertTrue(t1.wasNotAfter(t2));
        assertFalse(t2.wasNotAfter(t1));
    }

    @Test
    public void testNotEqualGeneralizedTime2() throws ParseException {
        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124355Z"));
        GeneralizedLogTime t2 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124356+0000"));


        assertTrue(t1.wasNotAfter(t2));
        assertFalse(t2.wasNotAfter(t1));
    }


    @Test
    public void testNotEqualGeneralizedTime3() throws ParseException {
        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124355Z"));
        GeneralizedLogTime t2 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124356-0000"));

        assertTrue(t1.wasNotAfter(t2));
        assertFalse(t2.wasNotAfter(t1));
    }



    @Test
    public void testDifferentGeneralizedTimes() throws ParseException {

        GeneralizedLogTime t1 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124355Z"));
        GeneralizedLogTime t2 = new GeneralizedLogTime(new ASN1GeneralizedTime("20200421124356Z"));

        assertTrue(t1.wasNotAfter(t2));
        assertFalse(t2.wasNotAfter(t1));
    }
}
