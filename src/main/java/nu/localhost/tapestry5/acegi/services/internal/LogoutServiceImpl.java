/*
 * Copyright 2007 Ivan Dubrov
 * Copyright 2007 Robin Helgelin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nu.localhost.tapestry.acegi.services.internal;

import java.util.List;

import nu.localhost.tapestry.acegi.services.LogoutService;

import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.ui.logout.LogoutHandler;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.services.RequestGlobals;

/**
 * @author Ivan Dubrov
 */
public class LogoutServiceImpl implements LogoutService {
    private List< LogoutHandler > handlers;
    private RequestGlobals requestGlobals;

    public LogoutServiceImpl(final List< LogoutHandler > handlers,
            @Inject final RequestGlobals requestGlobals) {
        this.handlers = handlers;
        this.requestGlobals = requestGlobals;
    }

    public final void logout() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        for (LogoutHandler handler : handlers) {
            handler.logout(requestGlobals.getHTTPServletRequest(), requestGlobals.getHTTPServletResponse(), auth);
        }
    }
}
