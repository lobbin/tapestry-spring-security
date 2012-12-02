package nu.localhost.tapestry5.springsecurity.validator;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import nu.localhost.tapestry5.springsecurity.pages.PermissionValidatorTestPage;

import org.apache.tapestry5.dom.Document;
import org.apache.tapestry5.dom.Element;
import org.apache.tapestry5.test.PageTester;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Tests for PermissionValidator validator with Tapestry.
 * 
 * @author ferengra
 */
public class PermissionValidatorTapestryTest {

    private static final String FORM = "form";
    private static final String FIELD = "field";
    private static final String PROTECTED_FIELD = "protectedField";
    private static final String LIST_FIELD = "protectedListField";
    private static final String FIELD_VALUE = "protectedValueSubmitted";
    private static final String PERMISSION = "permissionValue";

    private static final String USER = "user";

    private PageTester pageTester;

    @BeforeClass
    public void setUpClass() {
        pageTester = new PageTester("nu.localhost.tapestry5.springsecurity", "App", "src/test/resources",
            PermissionValidatorTestPage.class);
    }

    @AfterMethod
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void notSubmitted() {
        Document document = pageTester.renderPage(PermissionValidatorTestPage.class.getSimpleName());
        Element element = document.getElementById(PROTECTED_FIELD);
        assertNotNull(element);
        assertNull(element.getAttribute("class"));
        Element form = document.getElementById(FORM);
        assertNotNull(form);
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(FIELD, FIELD_VALUE);
        document = pageTester.submitForm(form, parameters);
        element = document.getElementById(PROTECTED_FIELD);
        assertNotNull(element);
        assertNull(element.getAttribute("class"));
        assertNull(element.getAttribute("value"));
        assertFalse(document.toString().contains("t-banner"));
    }

    @Test
    public void notAuthorized() {
        Document document = pageTester.renderPage(PermissionValidatorTestPage.class.getSimpleName());
        Element element = document.getElementById(PROTECTED_FIELD);
        assertNotNull(element);
        assertNull(element.getAttribute("class"));
        Element form = document.getElementById(FORM);
        assertNotNull(form);
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(FIELD, FIELD_VALUE);
        parameters.put(PROTECTED_FIELD, FIELD_VALUE);
        document = pageTester.submitForm(form, parameters);
        element = document.getElementById(PROTECTED_FIELD);
        assertNotNull(element);
        assertTrue(element.getAttribute("class").contains("error"));
        assertTrue(element.getAttribute("value").contains(FIELD_VALUE));
        // assertTrue(document.toString().contains("t-banner"));
    }

    @Test
    public void authorized() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(USER, null, PERMISSION));
        Document document = pageTester.renderPage(PermissionValidatorTestPage.class.getSimpleName());
        Element element = document.getElementById(PROTECTED_FIELD);
        assertNotNull(element);
        assertNull(element.getAttribute("class"));
        Element form = document.getElementById(FORM);
        assertNotNull(form);
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(FIELD, FIELD_VALUE);
        parameters.put(PROTECTED_FIELD, FIELD_VALUE);
        document = pageTester.submitForm(form, parameters);
        element = document.getElementById(PROTECTED_FIELD);
        assertNotNull(element);
        assertNull(element.getAttribute("class"));
        assertNull(element.getAttribute("value"));
        assertFalse(document.toString().contains("t-banner"));
    }

    @Test
    public void notAuthorizedList() {
        Document document = pageTester.renderPage(PermissionValidatorTestPage.class.getSimpleName());
        Element element = document.getElementById(LIST_FIELD);
        assertNotNull(element);
        assertNull(element.getAttribute("class"));
        Element form = document.getElementById(FORM);
        assertNotNull(form);
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(LIST_FIELD, FIELD_VALUE);
        document = pageTester.submitForm(form, parameters);
        element = document.getElementById(LIST_FIELD);
        assertNotNull(element);
        assertTrue(element.getAttribute("class").contains("error"));
        assertTrue(element.getAttribute("value").contains(FIELD_VALUE));
        // assertTrue(document.toString().contains("t-banner"));
    }

    @Test
    public void authorizedList() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(USER, null, PERMISSION));
        Document document = pageTester.renderPage(PermissionValidatorTestPage.class.getSimpleName());
        Element element = document.getElementById(LIST_FIELD);
        assertNotNull(element);
        assertNull(element.getAttribute("class"));
        Element form = document.getElementById(FORM);
        assertNotNull(form);
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(LIST_FIELD, FIELD_VALUE);
        document = pageTester.submitForm(form, parameters);
        element = document.getElementById(LIST_FIELD);
        assertNotNull(element);
        assertNull(element.getAttribute("class"));
        assertNull(element.getAttribute("value"));
        assertFalse(document.toString().contains("t-banner"));
    }
}
