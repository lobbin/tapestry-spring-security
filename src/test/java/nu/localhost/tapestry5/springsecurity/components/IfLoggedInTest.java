package nu.localhost.tapestry5.springsecurity.components;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import org.apache.tapestry5.Block;
import org.apache.tapestry5.internal.services.RequestGlobalsImpl;
import org.apache.tapestry5.services.RequestGlobals;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class IfLoggedInTest
{
    private static final String USER = "user";

    private IfLoggedIn victim;

    private RequestGlobals requestGlobals;
    private MockHttpServletRequest httpServletRequest;

    @BeforeMethod
    public void setUp()
    {
        victim = new IfLoggedIn();
        requestGlobals = new RequestGlobalsImpl();
        httpServletRequest = new MockHttpServletRequest();
        requestGlobals.storeServletRequestResponse(httpServletRequest, null);
        ReflectionTestUtils.setField(victim, "requestGlobals", requestGlobals);
    }

    @Test
    public void beforeRenderBodyNoPrincipal()
    {
        assertFalse(victim.beforeRenderBody());
    }

    @Test
    public void beforeRenderBody()
    {
        httpServletRequest.setUserPrincipal(new TestingAuthenticationToken(USER, null));
        assertTrue(victim.beforeRenderBody());
    }

    @Test
    public void beginRender()
    {
        Block block = mock(Block.class);
        ReflectionTestUtils.setField(victim, "elseBlock", block);
        httpServletRequest.setUserPrincipal(new TestingAuthenticationToken(USER, null));
        assertNull(victim.beginRender());
    }

    @Test
    public void beginRenderElse()
    {
        Block block = mock(Block.class);
        ReflectionTestUtils.setField(victim, "elseBlock", block);
        assertEquals(victim.beginRender(), block);
    }
}
