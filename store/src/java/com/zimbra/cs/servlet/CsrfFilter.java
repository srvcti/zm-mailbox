/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2013, 2014, 2015, 2016 Synacor, Inc.
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

package com.zimbra.cs.servlet;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.stream.Stream;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.common.base.Joiner;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.net.HttpHeaders;
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.StringUtil;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.CsrfTokenKey;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.servlet.util.CsrfUtil;
import com.zimbra.soap.RequestContext;

/**
 * @author zimbra
 *
 */
public class CsrfFilter implements Filter {

    /**
     *
     */
    public static final String CSRF_SALT = "CSRF_SALT";

    private String[] allowedRefHosts = null;

    private LoadingCache<String, String[]> domainAllowedRefHosts = null;

    public static final String AUTH_TOKEN = "AuthToken";

    public static final String CSRF_TOKEN_CHECK = "CsrfTokenCheck";

    protected int maxCsrfTokenValidityInMs;

    private Random nonceGen = null;

    private static final String[] EMPTY_ARRAY = new String[0];

    private static final int DEFAULT_DOMAIN_CACHE_EXPIRY_MINS = 60;

    /*
     * (non-Javadoc)
     *
     * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialize the parameters related to CSRF check
        Provisioning prov = Provisioning.getInstance();
        try {
            this.allowedRefHosts = prov.getConfig().getCsrfAllowedRefererHosts();
            this.domainAllowedRefHosts = buildDomainAllowedReferrerHostsCache();
            nonceGen = new Random();
            CsrfTokenKey.getCurrentKey();
            if (ZimbraLog.misc.isInfoEnabled()) {
                ZimbraLog.misc.info("CSRF filter was initialized: "
                        + "CSRFAllowedRefHost: [" + Joiner.on(", ").join(this.allowedRefHosts) + "]");
            }
        } catch (ServiceException e) {
            throw new ServletException("Error initializing CSRF filter: "
                + e.getMessage(), e);
        }

    }

    /*
     * (non-Javadoc)
     *
     * @see javax.servlet.Filter#destroy()
     */
    @Override
    public void destroy() {

        ZimbraLog.filter.info("Destroying CSRF filter.");

    }

    /*
     * (non-Javadoc)
     *
     * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest,
     * javax.servlet.ServletResponse, javax.servlet.FilterChain)
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        ZimbraLog.clearContext();

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        req.setAttribute(CSRF_SALT, nonceGen.nextInt() + 1);

        if (ZimbraLog.misc.isDebugEnabled()) {
             ZimbraLog.misc.debug("CSRF Request URI: " + req.getRequestURI());
        }

        boolean csrfCheckEnabled = Boolean.FALSE;
        boolean csrfRefererCheckEnabled = Boolean.FALSE;
        Provisioning prov = Provisioning.getInstance();
        try {
            csrfCheckEnabled = prov.getConfig().isCsrfTokenCheckEnabled();
            csrfRefererCheckEnabled = prov.getConfig().isCsrfRefererCheckEnabled();
        } catch (ServiceException e) {
            ZimbraLog.misc.info("Error in CSRF filter." + e.getMessage(), e);
        }

        if (ZimbraLog.misc.isDebugEnabled()) {
            ZimbraLog.misc.debug(
                    "CSRF filter was initialized : " + "CSRFcheck enabled: " +
                            csrfCheckEnabled + "CSRF referer check enabled: " +
                            csrfRefererCheckEnabled + ", CSRFAllowedRefHost: [" +
                            Joiner.on(", ").join(this.allowedRefHosts) + "]"
                            + ", CSRFTokenValidity " + this.maxCsrfTokenValidityInMs +
                            "ms." + " (domain-level overrides, if any, are logged per-request)");
        }

        if (ZimbraLog.misc.isTraceEnabled()) {
            Enumeration<String> hdrNames = req.getHeaderNames();
            ZimbraLog.misc.trace("Soap request headers.");
            while (hdrNames.hasMoreElements()) {
                String name = hdrNames.nextElement();
                // we do not want to print cookie headers for security reasons.
                if (name.contains(HttpHeaders.COOKIE))
                    continue;
                ZimbraLog.misc.trace(name + "=" + req.getHeader(name));
            }
        }
        String host = CsrfUtil.getRequestHost(req);
        if (csrfRefererCheckEnabled) {
            if (!allowReqBasedOnRefererHeaderCheck(req, host)) {
                ZimbraLog.misc.info("CSRF referer check failed");
                resp.sendError(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
        }

        // we need virtual host information in DefangFilter
        // set them in ThreadLocal here
        RequestContext reqCtxt = new RequestContext();
        reqCtxt.setVirtualHost(host);
        ZThreadLocal.setContext(reqCtxt);
        if (!csrfCheckEnabled) {
            req.setAttribute(CSRF_TOKEN_CHECK, Boolean.FALSE);
            chain.doFilter(req, resp);
        } else {
            req.setAttribute(Provisioning.A_zimbraCsrfTokenCheckEnabled, Boolean.TRUE);
            AuthToken authToken = CsrfUtil.getAuthTokenFromReq(req);
            if (CsrfUtil.doCsrfCheck(req, authToken)) {
                // post request and Auth token is CSRF enabled
                req.setAttribute(CSRF_TOKEN_CHECK, Boolean.TRUE);
            } else {
                req.setAttribute(CSRF_TOKEN_CHECK, Boolean.FALSE);
                ZimbraLog.misc.debug("CSRF check will not be done for URI : %s", req.getRequestURI());
            }
            chain.doFilter(req, resp);
        }
        ZThreadLocal.unset();

    }

    /**
     * @param initParameter
     * @return
     */
    protected static List<String> convertToList(String urlList) {
        List<String> urls = null;
        if (!StringUtil.isNullOrEmpty(urlList)) {
            String[] temp = urlList.split(",");
            for (int i = 0; i < temp.length; ++i) {
                temp[i] = temp[i].toLowerCase();
            }
            urls = Arrays.asList(temp);
        }
        return urls;
    }

    private boolean allowReqBasedOnRefererHeaderCheck(HttpServletRequest req, String virtualHost) {

        try {
            if (CsrfUtil.isCsrfRequestBasedOnReferrer(req, getEffectiveAllowedRefHosts(virtualHost))) {
                return false;
            }
        } catch (MalformedURLException e) {
            ZimbraLog.misc.info("Error while doing referer based check." + e.getMessage());
            return false;
        }
        return true;

    }

    /**
     * Builds the cache for domain level zimbraCsrfAllowedRefererHosts.
     * Max cache size is configurable by LC.csrf_filter_domain_allowed_ref_hosts_max_size.
     * Cache entries do not expire, requires mailbox restart to update after entry is stored.
     *
     * @return LoadingCache snapshot cache for each accessed domain's zimbraCsrfAllowedRefererHosts
     */
    protected LoadingCache<String, String[]> buildDomainAllowedReferrerHostsCache() {
        int maxCacheSize;
        try {
            maxCacheSize = LC.csrf_filter_domain_allowed_ref_hosts_max_size.intValue();
        } catch (NumberFormatException e) {
            ZimbraLog.misc.warn("Failed to determine CsrfFilter.domainAllowedRefHosts cache max size from" +
                            "LC.csrf_filter_domain_allowed_ref_hosts_max_size value, " +
                            "falling back to LC.ldap_cache_domain_maxsize", e);
            maxCacheSize = LC.ldap_cache_domain_maxsize.intValue();
        }
        int expiryMins;
        try {
            expiryMins = LC.csrf_filter_domain_allowed_ref_hosts_cache_expiry_mins.intValue();
            if (expiryMins <= 0) {
                ZimbraLog.misc.warn("CsrfFilter.domainAllowedRefHosts cache expiry must be > 0," +
                        " falling back to " + DEFAULT_DOMAIN_CACHE_EXPIRY_MINS + " minutes");
                expiryMins = DEFAULT_DOMAIN_CACHE_EXPIRY_MINS;
            }
        } catch (NumberFormatException e) {
            ZimbraLog.misc.warn("Failed to determine CsrfFilter.domainAllowedRefHosts cache expiry from "
                    + "LC.csrf_filter_domain_allowed_ref_hosts_cache_expiry_mins, falling back to  "
                    + DEFAULT_DOMAIN_CACHE_EXPIRY_MINS + " minutes", e);
            expiryMins = DEFAULT_DOMAIN_CACHE_EXPIRY_MINS;
        }

        return CacheBuilder.newBuilder()
                .maximumSize(maxCacheSize)
                .expireAfterWrite(expiryMins, java.util.concurrent.TimeUnit.MINUTES)
                .build(new CacheLoader<String, String[]>() {
                    // lazy load each domain's zimbraCsrfAllowedRefererHosts
                    @Override
                    public String[] load(String virtualHost) throws Exception {
                        try {
                            Provisioning prov = Provisioning.getInstance();
                            Domain domain = prov.getDomainByVirtualHostname(virtualHost);
                            if (domain == null) {
                                domain = prov.getDomainByName(virtualHost);
                            }
                            if (domain != null) { // ← null if no vhost set and name isn't a domain
                                String[] domainHosts = domain.getCsrfAllowedRefererHosts();
                                if (domainHosts != null && domainHosts.length > 0) {
                                    ZimbraLog.misc
                                            .debug("CSRF: additionally using domain-level allowedRefererHosts for"
                                                    + "virtualHost=%s, hosts=[%s]", virtualHost,
                                                    Joiner.on(", ").join(domainHosts));
                                    return Arrays.copyOf(domainHosts, domainHosts.length, String[].class);
                                }
                            }
                        } catch (ServiceException e) {
                            ZimbraLog.misc.warn(
                                    "CSRF: failed to resolve domain-level allowedRefererHosts for "
                                            + "virtualHost=%s, falling back to globalConfig.",
                                    virtualHost, e);
                        }
                        // always fallback to an empty list to prevent subsequent lookups for this virtual host
                        return EMPTY_ARRAY;
                    }
                });
    }

    /**
     * Returns effective CSRF allowed referer hosts for the current request.
     * Checks domain-level config first (via domainInherited flag) combining it
     * with the globalconfig-loaded allowedRefHosts, falls back to globalConfig-loaded
     * allowedRefHosts if domain not found or has no domain-level value.
     *
     * @param virtualHost the pre-resolved virtual host from CsrfUtil.getRequestHost()
     * @return array of allowed referer host strings for the resolved domain,
     * or the globalConfig allowedRefHosts if no domain-level value is found
     */
    protected String[] getEffectiveAllowedRefHosts(String virtualHost) {
        try {
            if (!StringUtil.isNullOrEmpty(virtualHost)) {
                // use both the global list and the domain specific list
                final String[] domainHosts = domainAllowedRefHosts.get(virtualHost);
                return Stream.of(this.allowedRefHosts, domainHosts)
                        .flatMap(Stream::of).distinct().toArray(String[]::new);
            }
        } catch (ExecutionException e) {
            ZimbraLog.misc.warn(
                    "CSRF: failed to resolve domain-level allowedRefererHosts for "
                            + "virtualHost=%s, falling back to globalConfig.",
                    virtualHost, e);
        }
        // fallback — preserves existing production behavior
        ZimbraLog.misc.debug(
                "CSRF: no domain-level allowedRefererHosts for virtualHost=%s, "
                        + "using globalConfig hosts=[%s]", virtualHost,
                Joiner.on(", ").join(this.allowedRefHosts));
        return this.allowedRefHosts;
    }

}
