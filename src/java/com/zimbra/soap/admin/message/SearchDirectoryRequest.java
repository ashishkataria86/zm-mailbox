/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2011 Zimbra, Inc.
 * 
 * The contents of this file are subject to the Zimbra Public License
 * Version 1.3 ("License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 * http://www.zimbra.com/license.
 * 
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied.
 * ***** END LICENSE BLOCK *****
 */

package com.zimbra.soap.admin.message;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;

import com.zimbra.common.soap.AdminConstants;
import com.zimbra.soap.type.AttributeSelectorImpl;
import com.zimbra.soap.type.ZmBoolean;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name=AdminConstants.E_SEARCH_DIRECTORY_REQUEST)
public class SearchDirectoryRequest extends AttributeSelectorImpl {

    @XmlAttribute(name=AdminConstants.E_QUERY, required=false)
    private String query;
    @XmlAttribute(name=AdminConstants.A_MAX_RESULTS, required=false)
    private Integer maxResults;
    @XmlAttribute(name=AdminConstants.A_LIMIT, required=false)
    private Integer limit;
    @XmlAttribute(name=AdminConstants.A_OFFSET, required=false)
    private Integer offset;
    @XmlAttribute(name=AdminConstants.A_DOMAIN, required=false)
    private String domain;
    @XmlAttribute(name=AdminConstants.A_APPLY_COS, required=false)
    private ZmBoolean applyCos;
    @XmlAttribute(name=AdminConstants.A_APPLY_CONFIG, required=false)
    private ZmBoolean applyConfig;
    @XmlAttribute(name=AdminConstants.A_SORT_BY, required=false)
    private String sortBy;
    @XmlAttribute(name=AdminConstants.A_TYPES, required=false)
    private String types;
    @XmlAttribute(name=AdminConstants.A_SORT_ASCENDING, required=false)
    private ZmBoolean sortAscending;

    public SearchDirectoryRequest() {
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public void setMaxResults(Integer maxResults) {
        this.maxResults = maxResults;
    }

    public void setLimit(Integer limit) {
        this.limit = limit;
    }

    public void setOffset(Integer offset) {
        this.offset = offset;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public void setApplyCos(Boolean applyCos) {
        this.applyCos = ZmBoolean.fromBool(applyCos);
    }

    public void setApplyConfig(Boolean applyConfig) {
        this.applyConfig = ZmBoolean.fromBool(applyConfig);
    }

    public void setSortBy(String sortBy) {
        this.sortBy = sortBy;
    }

    public void setTypes(String types) {
        this.types = types;
    }

    public void setSortAscending(Boolean sortAscending) {
        this.sortAscending = ZmBoolean.fromBool(sortAscending);
    }

    public String getQuery() { return query; }
    public Integer getMaxResults() { return maxResults; }
    public Integer getLimit() { return limit; }
    public Integer getOffset() { return offset; }
    public String getDomain() { return domain; }
    public Boolean getApplyCos() { return ZmBoolean.toBool(applyCos); }
    public Boolean getApplyConfig() { return ZmBoolean.toBool(applyConfig); }
    public String getSortBy() { return sortBy; }
    public String getTypes() { return types; }
    public Boolean getSortAscending() { return ZmBoolean.toBool(sortAscending); }
}
