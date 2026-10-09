/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2011, 2013, 2014, 2016 Synacor, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
package com.zimbra.cs.ldap.unboundid;

import java.security.GeneralSecurityException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import com.unboundid.util.ssl.SSLUtil;
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.net.SocketFactories;
import com.zimbra.common.net.TrustManagers;
import com.zimbra.cs.ldap.LdapException;

public class LdapSSLUtil {

    static {
        // Apply ldap_ssl_protocols config to the JVM client TLS protocol list at class load time.
        // This overrides the mailboxd_java_options value of jdk.tls.client.protocols specifically
        // for LDAP SSL contexts. Defaults to "TLSv1.2,TLSv1.3" to support both legacy and modern
        // LDAP servers. Setting it to "TLSv1.2" alone allows connection to servers that only
        // support TLS 1.2 without requiring a full JVM restart with modified java options.
        String ldapProtocols = LC.ldap_ssl_protocols.value();
        if (ldapProtocols != null && !ldapProtocols.isEmpty()) {
            System.setProperty("jdk.tls.client.protocols", ldapProtocols.trim());
        }
    }

    /*
    private static final LdapSSLUtil SINGLETON = new LdapSSLUtil();
    
    private static SSLUtil sslUtil;
    
    static LdapSSLUtil getInstance() {
        return SINGLETON;
    }
    
    private LdapSSLUtil() {
        boolean allowUntrustedCerts = LC.ssl_allow_untrusted_certs.booleanValue();
        TrustManager tm = getTrustManager(allowUntrustedCerts);
        sslUtil = new SSLUtil(tm);
    }
    
    private TrustManager getTrustManager(boolean allowUntrustedCerts) {
        if (allowUntrustedCerts) {
            return TrustManagers.dummyTrustManager();
        } else {
            return TrustManagers.customTrustManager();
        }
    }
    
    synchronized SSLSocketFactory createSocketFactory() throws LdapException {
        try {
            return sslUtil.createSSLSocketFactory();
        } catch (GeneralSecurityException e) {
            throw LdapException.LDAP_ERROR(e);
        }
    }
    
    synchronized SSLContext createSSLContext() throws LdapException  {
        try {
            return sslUtil.createSSLContext();
        } catch (GeneralSecurityException e) {
            throw LdapException.LDAP_ERROR(e);
        }
    }
    */
    
    static SSLSocketFactory createSSLSocketFactory(boolean allowUntrustedCerts) {
        if (allowUntrustedCerts) {
            return SocketFactories.dummySSLSocketFactory();
        } else {
            return SocketFactories.defaultSSLSocketFactory();
        }
    }
    
    private static TrustManager getTrustManager(boolean allowUntrustedCerts) {
        if (allowUntrustedCerts) {
            return TrustManagers.dummyTrustManager();
        } else {
            return TrustManagers.customTrustManager();
        }
    }
    
    static SSLContext createSSLContext(boolean allowUntrustedCerts) throws LdapException {
        TrustManager tm = getTrustManager(allowUntrustedCerts);
        SSLUtil sslUtil = new SSLUtil(tm);

        // Use "TLS" protocol so the JVM selects the highest mutually supported TLS version.
        // UnboundID SDK 7.x changed the no-arg createSSLContext() to default to TLSv1.3 only,
        // which breaks connections to LDAP servers that support only TLS 1.2 (ZCS-21319).
        // Protocol selection is governed by jdk.tls.client.protocols, initialized at class load
        // time from ldap_ssl_protocols localconfig (default: TLSv1.2,TLSv1.3).
        try {
            return sslUtil.createSSLContext("TLS");
        } catch (GeneralSecurityException e) {
            throw UBIDLdapException.mapToLdapException(e);
        }
    }
}
