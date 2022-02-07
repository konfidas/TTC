package de.konfidas.ttc.messages.systemlogs;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import org.bouncycastle.asn1.*;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.ResourceBundle;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class LockTransactionLoggingLogMessageTest {

    static Locale locale = new Locale("de", "DE");
    static ResourceBundle properties = ResourceBundle.getBundle("ttc", locale);

    @Test
    public void testLockTransactionLogMessage_SetUserIdAsString_ShouldGetUserIdAsString() throws BadFormatForLogMessageException {
        LockTransactionLoggingLogMessage message = new LockTransactionLoggingLogMessage(new byte[0], null);
        message.setUserIDAsString("foobar");
        assertEquals("foobar", message.getUserIDAsString());
    }

    @Test
    public void testLockTransactionLogMessage_SetUserId_ShouldGetUserId() throws BadFormatForLogMessageException {
        DLTaggedObject object = mock(DLTaggedObject.class);
        LockTransactionLoggingLogMessage message = new LockTransactionLoggingLogMessage(new byte[0], null);
        message.setUserID(object);
        assertEquals(object, message.getUserID());
    }

    @Test
    public void testLockTransactionLogMessage_FilenameIsNull_ShouldBeOk() throws BadFormatForLogMessageException {
        new LockTransactionLoggingLogMessage(new byte[0], null);
    }

    @Test
    public void testLockTransactionLogMessage_ContentIsNull_ShouldThrowNPE() throws BadFormatForLogMessageException {
        try {
            new LockTransactionLoggingLogMessage(null, "");
            fail();
        } catch (NullPointerException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testLockTransactionLogMessage_ContentAndFilenameAreNull_ShouldThrowNPE() throws BadFormatForLogMessageException {
        try {
            new LockTransactionLoggingLogMessage(null, null);
            fail();
        } catch (NullPointerException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testLockTransactionLogMessage_ShouldSetFilename() throws BadFormatForLogMessageException {
        String filename = "foobar";
        LockTransactionLoggingLogMessage message = new LockTransactionLoggingLogMessage(new byte[0], filename);
        assertEquals(filename, message.getFileName());
    }

    @Test
    public void testLockTransactionLogMessage_ShouldSetContent() throws BadFormatForLogMessageException {
        byte[] content = {0, 3, 4};
        LockTransactionLoggingLogMessage message = new LockTransactionLoggingLogMessage(content, "");
        assertEquals(content, message.getEncoded());
    }

    @Test
    public void testParseSystemOperationDataContent_StreamIsNull_ShouldThrowNPE() throws BadFormatForLogMessageException, IOException {
        LockTransactionLoggingLogMessage message = new LockTransactionLoggingLogMessage(new byte[0], "");
        try {
            message.parseSystemOperationDataContent(null);
            fail();
        } catch (NullPointerException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testParseSystemOperationDataContent_StreamIsNotASequence_ShouldAddErrorAndThrowException() throws BadFormatForLogMessageException, IOException {

        ASN1InputStream stream = mock(ASN1InputStream.class);
        when(stream.readObject()).thenReturn(mock(ASN1Primitive.class));

        LockTransactionLoggingLogMessage message = new LockTransactionLoggingLogMessage(new byte[0], "");

        try {
            message.parseSystemOperationDataContent(stream);
            fail();
        } catch (ClassCastException e) {
            assertEquals(1, message.getAllErrors().size());
            assertTrue(message.getAllErrors().get(0).getMessage().contains(properties.getString("de.konfidas.ttc.messages.systemlogs.errorParsingSystemOperationDataContent")));
        }
    }

    @Test
    public void testParseSystemOperationDataContent_UserIdMissing_ShouldAddError() throws BadFormatForLogMessageException, IOException {

        ASN1InputStream stream = mock(ASN1InputStream.class);
        ASN1Sequence sequence = mock(ASN1Sequence.class);
        Enumeration list = mock(Enumeration.class);
        DLTaggedObject object = mock(DLTaggedObject.class);
        DEROctetString primitive = mock(DEROctetString.class);
        when(primitive.getOctets()).thenReturn(new byte[0]);
        when(object.getObject()).thenReturn(primitive);
        when(list.hasMoreElements()).thenReturn(Boolean.TRUE).thenReturn(Boolean.TRUE).thenReturn(Boolean.FALSE);
        when(list.nextElement()).thenReturn(object);
        when(sequence.getObjects()).thenReturn(list);
        when(stream.readObject()).thenReturn(sequence);

        LockTransactionLoggingLogMessage message = new LockTransactionLoggingLogMessage(new byte[0], "");

        message.parseSystemOperationDataContent(stream);

        assertEquals(1, message.getAllErrors().size());
        assertTrue(message.getAllErrors().get(0).getMessage().contains(properties.getString("de.konfidas.ttc.messages.systemlogs.errorUserIDNotFound")));
    }

    @Test
    public void testParseSystemOperationDataContent_UserIdPresent_ShouldNotAddError() throws BadFormatForLogMessageException, IOException {

        ASN1InputStream stream = mock(ASN1InputStream.class);
        ASN1Sequence sequence = mock(ASN1Sequence.class);
        Enumeration list = mock(Enumeration.class);
        DLTaggedObject object = mock(DLTaggedObject.class);
        DEROctetString primitive = mock(DEROctetString.class);
        when(primitive.getOctets()).thenReturn(new byte[0]);
        when(object.getObject()).thenReturn(primitive);
        when(object.getTagNo()).thenReturn(1);
        when(list.hasMoreElements()).thenReturn(Boolean.TRUE).thenReturn(Boolean.TRUE).thenReturn(Boolean.FALSE);
        when(list.nextElement()).thenReturn(object);
        when(sequence.getObjects()).thenReturn(list);
        when(stream.readObject()).thenReturn(sequence);

        LockTransactionLoggingLogMessage message = new LockTransactionLoggingLogMessage(new byte[0], "");

        message.parseSystemOperationDataContent(stream);

        assertEquals(0, message.getAllErrors().size());
    }

}
