package nu.localhost.tapestry5.springsecurity.components;

import static org.testng.Assert.assertNull;
import nu.localhost.tapestry5.springsecurity.pages.IfLoggedInTestPage;

import org.apache.tapestry5.dom.Document;
import org.apache.tapestry5.test.PageTester;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class IfLoggedInTapestryTest
{
    private static final String FIELD = "protectedField";

    private PageTester pageTester;

    @BeforeClass
    public void setUpClass() {
        pageTester = new PageTester("nu.localhost.tapestry5.springsecurity", "App", "src/test/resources",
            IfLoggedInTestPage.class);
    }

    @Test
    public void notLoggedIn() {
        Document document = pageTester.renderPage(IfLoggedInTestPage.class.getSimpleName());
        assertNull(document.getElementById(FIELD));
    }
}
