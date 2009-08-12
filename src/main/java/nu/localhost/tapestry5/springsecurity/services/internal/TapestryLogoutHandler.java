package nu.localhost.tapestry5.springsecurity.services.internal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.services.RequestGlobals;
import org.apache.tapestry5.services.Session;
import org.springframework.security.Authentication;
import org.springframework.security.ui.logout.LogoutHandler;

public class TapestryLogoutHandler implements LogoutHandler {

    private RequestGlobals globals;
    
    public TapestryLogoutHandler( @Inject RequestGlobals globals ) {

        this.globals = globals;
    }

    public void logout( HttpServletRequest request, HttpServletResponse response, Authentication authentication ) {

        Session session = globals.getRequest().getSession( false );
        if ( null != session ) session.invalidate();
    }

}
