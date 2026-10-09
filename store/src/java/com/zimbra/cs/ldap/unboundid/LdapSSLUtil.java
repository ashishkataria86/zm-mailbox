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
import java.security.Security;
import java.util.Arrays;
import java.util.stream.Collectors;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import com.unboundid.util.ssl.SSLUtil;
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.net.SocketFactories;
import com.zimbra.common.net.TrustManagers;
import com.zimbra.cs.ldap.LdapException;

public class LdapSSLUtil {

    // Java 17.0.18 added "TLS_RSA_" to jdk.tls.disabledAlgorithms as a single prefix entry,
    // disabling all TLS_RSA_* (RSA key-exchange, no forward secrecy) cipher suites.
    // See: https://www.oracle.com/java/technologies/javase/17-0-18-relnotes.html
    private static final String TLS_RSA_DISABLED_ENTRY = "TLS_RSA_";

    static {
        if (LC.ldap_ssl_allow_legacy_rsa_ciphers.booleanValue()) {
            // Re-enable TLS_RSA_* cipher suites by removing the "TLS_RSA_" prefix entry that
            // Java 17.0.18 added to jdk.tls.disabledAlgorithms. External LDAP/AD servers that
            // only offer RSA key-exchange cipher suites fail the TLS handshake without this.
            // Per Oracle's release notes, users may re-enable these at their own risk by
            // removing "TLS_RSA_" from jdk.tls.disabledAlgorithms — this does that programmatically.
            String disabled = Security.getProperty("jdk.tls.disabledAlgorithms");
            if (disabled != null && disabled.contains(TLS_RSA_DISABLED_ENTRY)) {
                String updated = Arrays.stream(disabled.split(","))
                    .map(String::trim)
                    .filter(entry -> !entry.equalsIgnoreCase(TLS_RSA_DISABLED_ENTRY))
                    .collect(Collectors.joining(", "));
                Security.setProperty("jdk.tls.disabledAlgorithms", updated);
            }
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
