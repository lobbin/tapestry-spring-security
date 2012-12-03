package nu.localhost.tapestry5.springsecurity.validator;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

import org.apache.tapestry5.Field;
import org.apache.tapestry5.ValidationException;
import org.apache.tapestry5.ioc.MessageFormatter;
import org.apache.tapestry5.services.FormSupport;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Tests for PermissionValidator validator.
 * 
 * @author ferengra
 */
public class PermissionValidatorTest {

    private static final String USER = "user";
    private static final String PERMISSION = "permissionValue";
    private static final String LABEL = "label";

    private PermissionValidator victim;

    private Field field;
    private MessageFormatter formatter;

    @BeforeMethod
    public void setUp() {
        victim = new PermissionValidator();
        field = mock(Field.class);
        when(field.getLabel()).thenReturn(LABEL);
        formatter = mock(MessageFormatter.class);
        when(formatter.format(PERMISSION, LABEL)).thenReturn(PermissionValidator.MESSAGE);
    }

    @AfterMethod
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test(expectedExceptions = {ValidationException.class})
    public void validateNoAuthentication() throws ValidationException {
        try {
            victim.validate(field, PERMISSION, formatter, null);
            fail("Expected exception");
        } catch (ValidationException e) {
            assertEquals(e.getMessage(), PermissionValidator.MESSAGE);
            throw e;
        }
    }

    @Test
    public void validate() throws ValidationException {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(USER, null, PERMISSION));
        victim.validate(field, PERMISSION, formatter, null);
    }

    @Test
    public void validateList() throws ValidationException {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(USER, null, PERMISSION));
        victim.validate(field, "dummy;" + PERMISSION, formatter, null);
    }

    @Test(expectedExceptions = {ValidationException.class})
    public void validateException() throws ValidationException {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(USER, null));
        try {
            victim.validate(field, PERMISSION, formatter, null);
            fail("Expected exception");
        } catch (ValidationException e) {
            assertEquals(e.getMessage(), PermissionValidator.MESSAGE);
            verify(field).getLabel();
            verify(formatter).format(PERMISSION, LABEL);
            throw e;
        }
    }

    @Test
    public void render() throws ValidationException {
        FormSupport formSupport = mock(FormSupport.class);
        victim.render(field, PERMISSION, formatter, null, formSupport);
        verify(field).getLabel();
        verify(formatter).format(PERMISSION, LABEL);
        verify(formSupport).addValidation(field, PermissionValidator.NAME, PermissionValidator.MESSAGE, PERMISSION);
    }
}
