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

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.AttributeCallback;
import com.zimbra.cs.account.Entry;

/**
 * Validates zimbraMtaMyNetworks attribute values before they are written to LDAP.
 *
 * <p>Each value must be a valid network specification accepted by Postfix mynetworks and
 * amavisd @mynetworks: an IPv4 address, IPv4 CIDR block, IPv6 address (optionally bracketed),
 * IPv6 CIDR block, or a plain hostname/domain. Only characters that are meaningful in these
 * formats are permitted; any other character (including Perl metacharacters) is rejected to
 * prevent template-injection RCE via the amavisd.conf.in substitution performed by zmconfigd.
 *
 * <p>See ZCS-XXXXX / ZS-12 for the vulnerability this addresses.
 */
public class MtaMyNetworks extends AttributeCallback {

    /**
     * Accepts a single network token in any of the forms that Postfix mynetworks supports:
     * <ul>
     *   <li>IPv4: {@code 192.168.1.0/24}, {@code 127.0.0.1}
     *   <li>IPv6 bare: {@code ::1/128}, {@code 2001:db8::/32}
     *   <li>IPv6 bracketed (amavisd style): {@code [::1]/128}, {@code [2001:db8::]/32}
     *   <li>Hostname / domain: {@code localhost}, {@code example.com}
     * </ul>
     * The pattern deliberately excludes whitespace (values are split on whitespace before
     * individual validation) and all Perl metacharacters.
     */
    private static final Pattern VALID_NETWORK_TOKEN = Pattern.compile(
        "^(?:" +
            // IPv4 CIDR or plain address: digits and dots, optional /prefix
            "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?" +
            "|" +
            // IPv6 bracketed (amavisd @mynetworks style): [addr]/prefix or [addr]
            "\\[(?:[0-9a-fA-F:]+)\\](?:/[0-9]{1,3})?" +
            "|" +
            // IPv6 bare: hex groups and colons, optional /prefix
            "[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?:/[0-9]{1,3})?" +
            "|" +
            // Hostname / domain: letters, digits, hyphens, dots
            "[a-zA-Z0-9](?:[a-zA-Z0-9\\-\\.]*[a-zA-Z0-9])?" +
        ")$"
    );

    @Override
    public void preModify(CallbackContext context, String attrName, Object value,
            Map attrsToModify, Entry entry)
            throws ServiceException {

        MultiValueMod mod = multiValueMod(attrsToModify, attrName);
        if (mod == null || mod.deleting()) {
            return;
        }

        List<String> values = mod.values();
        if (values == null) {
            return;
        }

        for (String networkSpec : values) {
            if (networkSpec == null || networkSpec.isEmpty()) {
                continue;
            }
            validateNetworkSpec(attrName, networkSpec);
        }
    }

    @Override
    public void postModify(CallbackContext context, String attrName, Entry entry) {
        // nothing to do post-modify
    }

    /**
     * Validates a single network specification string (which may itself contain
     * multiple whitespace-delimited tokens, as Postfix allows the attribute to be
     * stored as a single multi-word string value).
     */
    private void validateNetworkSpec(String attrName, String networkSpec) throws ServiceException {
        // Split on whitespace — each token must independently be a valid network entry.
        String[] tokens = networkSpec.trim().split("\\s+");
        for (String token : tokens) {
            if (token.isEmpty()) {
                continue;
            }
            if (!VALID_NETWORK_TOKEN.matcher(token).matches()) {
                throw ServiceException.INVALID_REQUEST(
                    attrName + " contains an invalid network specification: '" + token +
                    "'. Only IP addresses, CIDR blocks, and hostnames are permitted.", null);
            }
        }
    }
}
