/*
 * Copyright 2007 Robin Helgelin
 * Copyright 2008 Jonathan Barker
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

package nu.localhost.tapestry5.springsecurity.components;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.tapestry5.BindingConstants;
import org.apache.tapestry5.Block;
import org.apache.tapestry5.annotations.Parameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Render it's body depending whether the user is in a specific role or not.<br/>
 * <i>Usage in tml:</i>
 * 
 * <pre>
 * &lt;t:security.ifRole ifAnyGranted="PERMISSION_MENU"&gt;
 *  &lt;td&gt;&lt;label&gt;${message:value-label}:&lt;/label&gt;&nbsp;${value}&lt;/td&gt;
 * &lt;/t:security.ifRole&gt;
 * </pre>
 * 
 * @author Jonathan Barker
 * @author Robin Helgelin
 * @author Tapestry Project (doc comments)
 */
public class IfRole {

    /** 
     * If the logged in user matches this role, then the body of the IfRole component is rendered. If false, the body is
     * omitted.  This is retained for backward compatibility, and corresponds to a single entry in ifAnyGranted
     */
    @Deprecated
    @Parameter(required = false, defaultPrefix = BindingConstants.LITERAL, principal = true)
    private String role;

    /**
     * A comma-separated list of roles is supplied to one or more of the
     * following parameters. If none are supplied, the default behavior is to
     * permit access. Behavior should be self-explanatory.
     */
    @Parameter(required = false, defaultPrefix = BindingConstants.LITERAL)
    private String ifAllGranted;

    @Parameter(required = false, defaultPrefix = BindingConstants.LITERAL)
    private String ifAnyGranted;

    @Parameter(required = false, defaultPrefix = BindingConstants.LITERAL)
    private String ifNotGranted;

    /**
     * Optional parameter to invert the test. If true, then the body is rendered when the test
     * parameter is false (not true).
     */
    @Parameter
    private boolean negate;

    /**
     * An alternate {@link Block} to render if the test parameter is false. The default, null, means
     * render nothing in that situation.
     */
    @Parameter(name = "else")
    private Block elseBlock;

    private boolean test;

    private Collection<GrantedAuthority> getPrincipalAuthorities() {
        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();

        if (null == currentUser)
        {
            return Collections.<GrantedAuthority> emptyList();
        }

        return currentUser.getAuthorities();
    }

    private Set<String> authoritiesToRoles(Collection<GrantedAuthority> c) {
        Set<String> target = new HashSet<String>();

        for (GrantedAuthority authority : c) {
            if (null == authority.getAuthority()) {
                throw new IllegalArgumentException(
                        "Cannot process GrantedAuthority objects which return null from getAuthority() - attempting to process " +
                                authority.toString());
            }

            target.add(authority.getAuthority());
        }

        return target;
    }

    private Collection<GrantedAuthority> parseAuthorities(String authorities) {
        Collection<GrantedAuthority> requiredAuthorities = new HashSet<GrantedAuthority>();
        for (String authority : authorities.split(",")) {
            requiredAuthorities.add(new GrantedAuthorityImpl(authority.replaceAll(" |\t|\r|\n|\f", "")));
        }

        return requiredAuthorities;
    }

    /**
     * Find the common authorities between the current authentication's {@link
     * GrantedAuthority} and the ones that have been specified in the tag's
     * ifAny, ifNot or ifAllGranted attributes.
     * 
     * <p>
     * We need to manually iterate over both collections, because the granted
     * authorities might not implement {@link Object#equals(Object)} and
     * {@link Object#hashCode()} in the same way as {@link
     * GrantedAuthorityImpl}, thereby invalidating {@link
     * Collection#retainAll(java.util.Collection)} results.
     * </p>
     * 
     * <p>
     * <strong>CAVEAT</strong>: This method <strong>will not</strong> work if
     * the granted authorities returns a <code>null</code> string as the
     * return value of {@link
     * org.springframework.security.GrantedAuthority#getAuthority()}.
     * </p>
     * 
     * <p>
     * Reported by rawdave, on Fri Feb 04, 2005 2:11 pm in the Spring Security
     * System for Spring forums.
     * </p>
     * 
     * @param granted
     *            The authorities granted by the authentication. May be any
     *            implementation of {@link GrantedAuthority} that does
     *            <strong>not</strong> return <code>null</code> from {@link
     *            org.springframework.security.GrantedAuthority#getAuthority()}.
     * @param required
     *            A {@link Set} of {@link GrantedAuthorityImpl}s that have been
     *            built using ifAny, ifAll or ifNotGranted.
     * 
     * @return A set containing only the common authorities between <var>granted</var>
     *         and <var>required</var>.
     * 
     */
    private Set<GrantedAuthority> retainAll(Collection<GrantedAuthority> granted, Collection<GrantedAuthority> required)
    {
        Set<String> grantedRoles = authoritiesToRoles(granted);
        Set<String> requiredRoles = authoritiesToRoles(required);
        grantedRoles.retainAll(requiredRoles);

        return rolesToAuthorities(grantedRoles, granted);
    }

    /**
     * @param grantedRoles
     * @param granted
     * @return a Set of Authorities corresponding to the roles in the grantedRoles
     * that are also in the granted Set of Authorities
     */
    private Set<GrantedAuthority> rolesToAuthorities(Set<String> grantedRoles, Collection<GrantedAuthority> granted) {
        Set<GrantedAuthority> target = new HashSet<GrantedAuthority>();

        for (String role : grantedRoles) {
            for (GrantedAuthority authority : granted) {
                if (authority.getAuthority().equals(role)) {
                    target.add(authority);
                    break;
                }
            }
        }

        return target;
    }

    /**
     * @return false as the default.  Returns true if all non-null role expressions are 
     * satisfied.  Typically, only one will be used, but if more than one are used, then 
     * the conditions are effectively AND'd 
     */
    private boolean checkPermission() {
        if (((null == ifAllGranted) || 0 == ifAllGranted.length())
            && ((null == ifAnyGranted) || 0 == ifAnyGranted.length())
         && ((null == role) || "".equals(role))
            && ((null == ifNotGranted) || 0 == ifNotGranted.length())) {
            return false;
        }

        Collection<GrantedAuthority> granted = getPrincipalAuthorities();

        if ((null != role) && !"".equals(role)) {
            Set<GrantedAuthority> grantedCopy = retainAll(granted, parseAuthorities(role));
            if (grantedCopy.isEmpty()) {
                return false;
            }
        }

        if ((null != ifNotGranted) && 0 < ifNotGranted.length()) {
            if (!retainAll(granted, parseAuthorities(ifNotGranted)).isEmpty()) {
                return false;
            }
        }

        if ((null != ifAllGranted) && 0 < ifAllGranted.length()) {
            if (!granted.containsAll(parseAuthorities(ifAllGranted))) {
                return false;
            }
        }

        if ((null != ifAnyGranted) && 0 < ifAnyGranted.length()) {
            if (retainAll(granted, parseAuthorities(ifAnyGranted)).isEmpty()) {
                return false;
            }
        }

        return true;
    }


    void setupRender() {
        test = checkPermission();
    }

    /**
     * Returns null if the test method returns true, which allows normal
     * rendering (of the body). If the test parameter is false, returns the else
     * parameter (this may also be null).
     */
    Object beginRender() {
        return test != negate ? null : elseBlock;
    }

    /**
     * If the test method returns true, then the body is rendered, otherwise not. The component does
     * not have a template or do any other rendering besides its body.
     */
    boolean beforeRenderBody() {
        return test != negate;
    }
}
