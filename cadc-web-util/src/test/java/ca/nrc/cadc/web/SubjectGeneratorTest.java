/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2017.                            (c) 2017.
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 *  All rights reserved                  Tous droits réservés
 *
 *  NRC disclaims any warranties,        Le CNRC dénie toute garantie
 *  expressed, implied, or               énoncée, implicite ou légale,
 *  statutory, of any kind with          de quelque nature que ce
 *  respect to the software,             soit, concernant le logiciel,
 *  including without limitation         y compris sans restriction
 *  any warranty of merchantability      toute garantie de valeur
 *  or fitness for a particular          marchande ou de pertinence
 *  purpose. NRC shall not be            pour un usage particulier.
 *  liable in any event for any          Le CNRC ne pourra en aucun cas
 *  damages, whether direct or           être tenu responsable de tout
 *  indirect, special or general,        dommage, direct ou indirect,
 *  consequential or incidental,         particulier ou général,
 *  arising from the use of the          accessoire ou fortuit, résultant
 *  software.  Neither the name          de l'utilisation du logiciel. Ni
 *  of the National Research             le nom du Conseil National de
 *  Council of Canada nor the            Recherches du Canada ni les noms
 *  names of its contributors may        de ses  participants ne peuvent
 *  be used to endorse or promote        être utilisés pour approuver ou
 *  products derived from this           promouvoir les produits dérivés
 *  software without specific prior      de ce logiciel sans autorisation
 *  written permission.                  préalable et particulière
 *                                       par écrit.
 *
 *  This file is part of the             Ce fichier fait partie du projet
 *  OpenCADC project.                    OpenCADC.
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la “GNU Affero General Public
 *  License as published by the          License” telle que publiée
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)         licence, soit (à votre gré)
 *  any later version.                   toute version ultérieure.
 *
 *  OpenCADC is distributed in the       OpenCADC est distribué
 *  hope that it will be useful,         dans l’espoir qu’il vous
 *  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 *  without even the implied             GARANTIE : sans même la garantie
 *  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
 *  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
 *  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 *  General Public License for           Générale Publique GNU Affero
 *  more details.                        pour plus de détails.
 *
 *  You should have received             Vous devriez avoir reçu une
 *  a copy of the GNU Affero             copie de la Licence Générale
 *  General Public License along         Publique GNU Affero avec
 *  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
 *  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 *                                       <http://www.gnu.org/licenses/>.
 *
 *
 ************************************************************************
 */

package ca.nrc.cadc.web;

import ca.nrc.cadc.accesscontrol.AccessControlUtil;

import ca.nrc.cadc.auth.CookiePrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.PrincipalExtractor;
import ca.nrc.cadc.auth.SSOCookieCredential;

import javax.security.auth.Subject;
import java.io.IOException;
import java.security.Principal;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import ca.nrc.cadc.auth.SSOCookieManager;
import ca.nrc.cadc.net.NetUtil;
import junit.framework.AssertionFailedError;
import org.json.Cookie;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;


public class SubjectGeneratorTest {

    @Test
    public void generate() throws Exception {
        final AccessControlUtil mockAccessControlUtil = mock(AccessControlUtil.class);
        final PrincipalExtractor mockPrincipalExtractor = mock(PrincipalExtractor.class);
        final Subject testUser = new Subject();
        final String cookieToken = UUID.randomUUID().toString();
        final Calendar expiryCalendar = Calendar.getInstance();
        expiryCalendar.add(Calendar.MONTH, 1);
        final SSOCookieCredential testSSOCookieCredential =
                new SSOCookieCredential(cookieToken, "example.cadc.ca", expiryCalendar.getTime());
        testUser.getPublicCredentials().add(testSSOCookieCredential);
        final SubjectGenerator testSubject = new SubjectGenerator(mockAccessControlUtil) {
            @Override
            Subject getSubject(PrincipalExtractor principalExtractor) {
                return testUser;
            }
        };
        final Set<String> domainServers = new HashSet<>();

        domainServers.add("mysite.example.com");
        domainServers.add("mysite.anotherplace.com");
        domainServers.add("mysite.onemore.com");

        when(mockAccessControlUtil.getSSOServers()).thenReturn(domainServers);

        final Set<String> allDomains = new HashSet<>();
        domainServers.forEach(domain -> {
            try {
                allDomains.add(NetUtil.getDomainName(domain));
            } catch (IOException ioException) {
                throw new RuntimeException(ioException.getMessage(), ioException);
            }
        });
        allDomains.add(NetUtil.getDomainName(testSSOCookieCredential.getDomain()));

        final Subject subject = testSubject.generate(mockPrincipalExtractor);
        final Set<SSOCookieCredential> cookieCredentials = subject.getPublicCredentials(SSOCookieCredential.class);

        // The main one set, as well as the three above
        assertEquals("Wrong cookie count.", allDomains.size(), cookieCredentials.size());
        cookieCredentials.forEach(cookieCredential -> {
            try {
                final String cookieCredDomain = NetUtil.getDomainName(cookieCredential.getDomain());
                assertTrue("Wrong domain (" + cookieCredDomain + ")", allDomains.contains(cookieCredDomain));
            } catch (IOException ioException) {
                throw new AssertionFailedError(ioException.getMessage());
            }
        });

        verify(mockAccessControlUtil, times(1)).getSSOServers();
    }
}
