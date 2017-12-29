/*
 * Copyright (c) 2017 Ignite Realtime Foundation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.spark.util;

import org.jivesoftware.Spark;
import org.jivesoftware.spark.ui.login.GSSAPIConfiguration;
import org.jivesoftware.spark.util.log.Log;
import org.jivesoftware.sparkimpl.settings.local.LocalPreferences;
import org.jivesoftware.sparkimpl.settings.local.SettingsManager;
import waffle.windows.auth.IWindowsCredentialsHandle;
import waffle.windows.auth.impl.WindowsAccountImpl;
import waffle.windows.auth.impl.WindowsCredentialsHandleImpl;
import waffle.windows.auth.impl.WindowsSecurityContextImpl;

import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.Principal;

/**
 * Utility methods that facilitate Spark's Single Sign-On functionality.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
public class SSOUtils
{
    /**
     * Returns the full Kerberos principal name (primary/instance@REALM.) if one exists.
     *
     * A Kerberos principal is a unique identity to which Kerberos can assign tickets. Principals can have an arbitrary
     * number of components. Each component is separated by a component separator, generally `/'. The last component is
     * the realm, separated from the rest of the principal by the realm separator, generally `@'. If there is no realm
     * component in the principal, then it will be assumed that the principal is in the default realm for the context in
     * which it is being used.
     *
     * Traditionally, a principal is divided into three parts: the primary, the instance, and the realm. The format of a
     * typical Kerberos V5 principal is primary/instance@REALM.
     *
     * The primary is the first part of the principal. In the case of a user, it's the same as your username.
     * For a host, the primary is the word host.
     *
     * The instance is an optional string that qualifies the primary. The instance is separated from the primary by a
     * slash (/). In the case of a user, the instance is usually null, but a user might also have an additional
     * principal, with an instance called admin, which he/she uses to administrate a database. The principal
     * jennifer@ATHENA.MIT.EDU is completely separate from the principal jennifer/admin@ATHENA.MIT.EDU, with a separate
     * password, and separate permissions. In the case of a host, the instance is the fully qualified hostname, e.g.,
     * daffodil.mit.edu.
     *
     * The realm is your Kerberos realm. In most cases, your Kerberos realm is your domain name, in upper-case letters.
     * For example, the machine daffodil.example.com would be in the realm EXAMPLE.COM.
     *
     * @return a principal name, or null if none is found.
     * @see <a href="https://web.mit.edu/kerberos/krb5-1.5/krb5-1.5.4/doc/krb5-user/What-is-a-Kerberos-Principal_003f.html">Kerberos V5 UNIX User's Guide</a>
     */
    public static String getKerberosName()
    {
        if ( Spark.isWindows() )
        {
            final IWindowsCredentialsHandle clientCredentials = WindowsCredentialsHandleImpl.getCurrent( "Kerberos" );
            clientCredentials.initialize();

            // initial client security context
            final WindowsSecurityContextImpl clientContext = new WindowsSecurityContextImpl();
            clientContext.setPrincipalName( WindowsAccountImpl.getCurrentUsername() );
            clientContext.setCredentialsHandle( clientCredentials );
            clientContext.setSecurityPackage( "Kerberos" );
            clientContext.initialize( null, null, WindowsAccountImpl.getCurrentUsername() );

            return clientContext.getPrincipalName();
        }
        else
        {
            final LocalPreferences localPreferences = SettingsManager.getLocalPreferences();
            if ( localPreferences.getDebug() )
            {
                System.setProperty( "java.security.krb5.debug", "true" );
            }
            System.setProperty( "javax.security.auth.useSubjectCredsOnly", "false" );

            String ssoMethod = localPreferences.getSSOMethod();
            if ( !ModelUtil.hasLength( ssoMethod ) )
            {
                ssoMethod = "file";
            }

            GSSAPIConfiguration config = new GSSAPIConfiguration( ssoMethod.equals( "file" ) );
            Configuration.setConfiguration( config );

            LoginContext lc;
            try
            {
                lc = new LoginContext( "com.sun.security.jgss.krb5.initiate" );
                lc.login();
            }
            catch ( LoginException le )
            {
                Log.debug( le.getMessage() );
                return null;
            }

            Subject mySubject = lc.getSubject();

            for ( Principal principal : mySubject.getPrincipals() )
            {
                String name = principal.getName();
                int indexOne = name.indexOf( "@" );
                // TODO: This is existing behavior from the old implementation. Shouldn't we check for the principal being an instance of KerberosPrincipal instead?
                if ( indexOne != -1 )
                {
                    return principal.getName();
                }
            }
            return null;
        }
    }

    /**
     * Return the Kerberos primary, if one exists (this typically is a username).
     *
     * Refer to the documentation o {@link #getKerberosName()} for more documentation on the Kerberos name composition.
     *
     * @return a Kerberos primary, or null if none is found.
     */
    public static String getKerberosPrimary()
    {
        final String name = getKerberosName();
        if ( name == null )
        {
            return null;
        }

        final int r = name.indexOf( System.getProperty( "kerberos.realm-separator", "@" ) );
        if ( r == -1 )
        {
            // The entire name is a realm.
            return null;
        }

        final int c = name.substring( 0, r ).indexOf( System.getProperty( "kerberos.component-separator", "/" ) );
        if ( c != -1 )
        {
            // Strip off all but the first component.
            return name.substring( 0, c );
        }

        // Strip off the realm.
        return name.substring( 0, r );
    }

    /**
     * Return the Kerberos instance, if one exists.
     *
     * If more than one non-primary component is present before the realm-part of the full Kerberos name, all of them
     * are returned, each separated by a component separator.
     *
     * Refer to the documentation o {@link #getKerberosName()} for more documentation on the Kerberos name composition.
     *
     * @return a Kerberos primary, or null if none is found.
     */
    public static String getKerberosInstance()
    {
        final String name = getKerberosName();
        if ( name == null )
        {
            return null;
        }

        final int r = name.indexOf( System.getProperty( "kerberos.realm-separator", "@" ) );
        if ( r == -1 )
        {
            // The entire name is a realm.
            return null;
        }

        final int c = name.substring( 0, r ).indexOf( System.getProperty( "kerberos.component-separator", "/" ) );
        if ( c == -1 )
        {
            // There's only a primary.
            return null;
        }

        // Strip off the primary, return the rest.
        return name.substring( c + 1, r );
    }

    /**
     * Return the Kerberos realm, if one exists (this typically is a domain name).
     *
     * Refer to the documentation o {@link #getKerberosName()} for more documentation on the Kerberos name composition.
     *
     * @return a Kerberos realm, or null if none is found.
     */
    public static String getKerberosRealm()
    {
        final String name = getKerberosName();
        if ( name == null )
        {
            return null;
        }

        final int r = name.indexOf( System.getProperty( "kerberos.realm-separator", "@" ) );
        if ( r == -1 )
        {
            // The entire name is a realm.
            return name;
        }
        else
        {
            return name.substring( r + 1 );
        }
    }
}
