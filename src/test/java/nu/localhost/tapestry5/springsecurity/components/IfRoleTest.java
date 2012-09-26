package nu.localhost.tapestry5.springsecurity.components;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import org.apache.tapestry5.Block;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class IfRoleTest
{
    private static final String USER = "user";
    private static final String PERMISSION = "permission";
    private static final String PERMISSION_2 = "permission2";

    private IfRole victim;

    @BeforeMethod
    public void setUp() {
        victim = new IfRole();
    }

    @AfterMethod
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void beforeRenderBodyNone() {
        victim.setupRender();
        assertFalse(victim.beforeRenderBody());
    }

    @Test
    public void beforeRenderBodyIfAllGrantedNot() {
        ReflectionTestUtils.setField(victim, "ifAllGranted", PERMISSION);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(USER, null));
        victim.setupRender();
        assertFalse(victim.beforeRenderBody());
    }

    @Test
    public void beforeRenderBodyIfAllGranted() {
        ReflectionTestUtils.setField(victim, "ifAllGranted", PERMISSION + "  \r," + PERMISSION_2);
        SecurityContextHolder.getContext().setAuthentication(
            new TestingAuthenticationToken(USER, null, PERMISSION, PERMISSION_2));
        victim.setupRender();
        assertTrue(victim.beforeRenderBody());
    }

    @Test
    public void beforeRenderBodyIfAnyGrantedNot() {
        ReflectionTestUtils.setField(victim, "ifAnyGranted", PERMISSION + "," + PERMISSION_2);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(USER, null));
        victim.setupRender();
        assertFalse(victim.beforeRenderBody());
    }

    @Test
    public void beforeRenderBodyIfAnyGranted() {
        ReflectionTestUtils.setField(victim, "ifAnyGranted", PERMISSION + ", \t" + PERMISSION_2);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(USER, null, PERMISSION));
        victim.setupRender();
        assertTrue(victim.beforeRenderBody());
    }

    @Test
    public void beforeRenderBodyIfNotGrantedNot() {
        ReflectionTestUtils.setField(victim, "ifNotGranted", PERMISSION + "," + PERMISSION_2);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(USER, null, PERMISSION));
        victim.setupRender();
        assertFalse(victim.beforeRenderBody());
    }

    @Test
    public void beforeRenderBodyIfNotGranted() {
        ReflectionTestUtils.setField(victim, "ifNotGranted", PERMISSION + "," + PERMISSION_2);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(USER, null));
        victim.setupRender();
        assertTrue(victim.beforeRenderBody());
    }

    @Test
    public void beginRender() {
        Block block = mock(Block.class);
        ReflectionTestUtils.setField(victim, "elseBlock", block);
        ReflectionTestUtils.setField(victim, "ifAnyGranted", PERMISSION);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(USER, null, PERMISSION));
        victim.setupRender();
        assertNull(victim.beginRender());
    }

    @Test
    public void beginRenderElse() {
        Block block = mock(Block.class);
        ReflectionTestUtils.setField(victim, "elseBlock", block);
        victim.setupRender();
        assertEquals(victim.beginRender(), block);
    }
}
