/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2024 Synacor, Inc.
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
package com.zimbra.cs.account.callback;

import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.Provisioning;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.fail;

/**
 * Unit tests for {@link MtaMyNetworks}, the AttributeCallback that validates
 * zimbraMtaMyNetworks values before they are written to LDAP.
 *
 * <p>Tests cover:
 * <ul>
 *   <li>Valid IPv4 addresses and CIDR blocks</li>
 *   <li>Valid IPv6 addresses and CIDR blocks (bare and bracketed)</li>
 *   <li>Valid hostnames</li>
 *   <li>Multi-token values (space-separated, as Postfix allows)</li>
 *   <li>Rejection of Perl metacharacters used in RCE payloads (ZCS-XXXXX)</li>
 *   <li>Rejection of shell metacharacters</li>
 *   <li>Deletion / null values (should be accepted silently)</li>
 * </ul>
 */
public class MtaMyNetworksTest {

    private static final String ATTR = Provisioning.A_zimbraMtaMyNetworks;
    private final MtaMyNetworks callback = new MtaMyNetworks();

    // -----------------------------------------------------------------------
    // Valid values — must NOT throw
    // -----------------------------------------------------------------------

    @Test
    public void testValidIPv4Address() throws ServiceException {
        assertValid("127.0.0.1");
    }

    @Test
    public void testValidIPv4CIDR() throws ServiceException {
        assertValid("127.0.0.0/8");
    }

    @Test
    public void testValidIPv4PrivateRange() throws ServiceException {
        assertValid("10.0.0.0/8");
    }

    @Test
    public void testValidIPv4MultipleTokens() throws ServiceException {
        assertValid("127.0.0.0/8 10.0.0.0/8 192.168.0.0/16");
    }

    @Test
    public void testValidIPv6Bare() throws ServiceException {
        assertValid("::1");
    }

    @Test
    public void testValidIPv6BareCIDR() throws ServiceException {
        assertValid("::1/128");
    }

    @Test
    public void testValidIPv6Full() throws ServiceException {
        assertValid("2001:db8::/32");
    }

    @Test
    public void testValidIPv6Bracketed() throws ServiceException {
        // amavisd @mynetworks uses [addr]/prefix notation
        assertValid("[::1]/128");
    }

    @Test
    public void testValidIPv6BracketedFull() throws ServiceException {
        assertValid("[2001:db8::]/32");
    }

    @Test
    public void testValidHostname() throws ServiceException {
        assertValid("localhost");
    }

    @Test
    public void testValidHostnameFQDN() throws ServiceException {
        assertValid("mail.example.com");
    }

    @Test
    public void testValidMixedTokens() throws ServiceException {
        assertValid("127.0.0.0/8 [::1]/128 10.0.0.0/8");
    }

    @Test
    public void testNullValue() throws ServiceException {
        // Deleting the attribute must succeed
        Map<String, Object> attrs = new HashMap<>();
        attrs.put(ATTR, null);
        callback.preModify(new CallbackContext(CallbackContext.Op.MODIFY), ATTR, null, attrs, null);
    }

    @Test
    public void testEmptyString() throws ServiceException {
        // Empty string signals deletion — must succeed
        Map<String, Object> attrs = new HashMap<>();
        attrs.put(ATTR, "");
        callback.preModify(new CallbackContext(CallbackContext.Op.MODIFY), ATTR, "", attrs, null);
    }

    // -----------------------------------------------------------------------
    // Invalid / malicious values — MUST throw ServiceException
    // -----------------------------------------------------------------------

    @Test
    public void testRejectedPerlInjectionClassic() {
        // Classic RCE payload from the bug report
        assertInvalid("); system('id > /tmp/pwned'); qw(");
    }

    @Test
    public void testRejectedPerlInjectionReverse() {
        // Reverse-shell variant
        assertInvalid("127.0.0.0/8 ); use Socket; ... qw(");
    }

    @Test
    public void testRejectedSemicolon() {
        assertInvalid("127.0.0.1;id");
    }

    @Test
    public void testRejectedParenthesis() {
        assertInvalid("127.0.0.1(");
    }

    @Test
    public void testRejectedBacktick() {
        assertInvalid("`id`");
    }

    @Test
    public void testRejectedDollarSign() {
        assertInvalid("$HOME");
    }

    @Test
    public void testRejectedPipe() {
        assertInvalid("127.0.0.1|cat /etc/passwd");
    }

    @Test
    public void testRejectedAmpersand() {
        assertInvalid("127.0.0.1&&id");
    }

    @Test
    public void testRejectedNewline() {
        assertInvalid("127.0.0.1\nid");
    }

    @Test
    public void testRejectedCarriageReturn() {
        assertInvalid("127.0.0.1\rid");
    }

    @Test
    public void testRejectedSingleQuote() {
        assertInvalid("'); system('id'); qw('");
    }

    @Test
    public void testRejectedDoubleQuote() {
        assertInvalid("127.0.0.1\"); system(\"id\"); qw(\"");
    }

    @Test
    public void testRejectedAngleBracket() {
        assertInvalid("127.0.0.0/8 <STDIN>");
    }

    @Test
    public void testRejectedAtSign() {
        // @ is a Perl array sigil
        assertInvalid("@mynetworks");
    }

    @Test
    public void testRejectedPercentSign() {
        assertInvalid("127.0.0.0/8 %ENV");
    }

    @Test
    public void testRejectedBackslash() {
        assertInvalid("127.0.0.0\\8");
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private void assertValid(String networkSpec) throws ServiceException {
        Map<String, Object> attrs = new HashMap<>();
        attrs.put(ATTR, networkSpec);
        callback.preModify(new CallbackContext(CallbackContext.Op.MODIFY),
                ATTR, networkSpec, attrs, null);
        // Must reach here without exception
    }

    private void assertInvalid(String networkSpec) {
        Map<String, Object> attrs = new HashMap<>();
        attrs.put(ATTR, networkSpec);
        try {
            callback.preModify(new CallbackContext(CallbackContext.Op.MODIFY),
                    ATTR, networkSpec, attrs, null);
            fail("Expected ServiceException for malicious value: " + networkSpec);
        } catch (ServiceException e) {
            // expected — validation correctly rejected the value
        }
    }
}
