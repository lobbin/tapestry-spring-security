package nu.localhost.tapestry5.springsecurity.components;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import nu.localhost.tapestry5.springsecurity.pages.IfRoleTestPage;

import org.apache.tapestry5.dom.Document;
import org.apache.tapestry5.test.PageTester;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class IfRoleTapestryTest
{
    private static final String FIELD_ANY = "protectedFieldAny";
    private static final String FIELD_NOT = "protectedFieldNot";
    private static final String FIELD_ALL = "protectedFieldAll";

    private static final String PERMISSION = "permission";
    private static final String PERMISSION_2 = "permission2";

    private static final String USER = "user";

    private PageTester pageTester;

    @BeforeClass
    public void setUpClass() {
        pageTester = new PageTester("nu.localhost.tapestry5.springsecurity", "App", "src/test/resources",
            IfRoleTestPage.class);
    }

    @AfterMethod
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void notAuthorized() {
        Document document = pageTester.renderPage(IfRoleTestPage.class.getSimpleName());
        assertNull(document.getElementById(FIELD_ANY));
        assertNotNull(document.getElementById(FIELD_NOT));
        assertNull(document.getElementById(FIELD_ALL));
    }

    @Test
    public void authorized() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(USER, null, PERMISSION));
        Document document = pageTester.renderPage(IfRoleTestPage.class.getSimpleName());
        assertNotNull(document.getElementById(FIELD_ANY));
        assertNull(document.getElementById(FIELD_NOT));
        assertNull(document.getElementById(FIELD_ALL));
    }

    @Test
    public void authorizedAll() {
        SecurityContextHolder.getContext().setAuthentication(
            new TestingAuthenticationToken(USER, null, PERMISSION, PERMISSION_2));
        Document document = pageTester.renderPage(IfRoleTestPage.class.getSimpleName());
        assertNotNull(document.getElementById(FIELD_ANY));
        assertNull(document.getElementById(FIELD_NOT));
        assertNotNull(document.getElementById(FIELD_ALL));
    }
}
