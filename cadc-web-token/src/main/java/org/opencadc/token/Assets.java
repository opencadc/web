/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2023.                            (c) 2023.
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

package org.opencadc.token;

import ca.nrc.cadc.util.StringUtil;
import org.json.JSONObject;

import java.util.Objects;

/**
 * Class that represents the document that will be stored in cache.  Instances can be updated from time to time
 * during a refresh.
 */
public final class Assets {
    // Provide a short buffer to check for the expiry time.  This will be used to ensure that the expiry time isn't
    // in the future by, say, one millisecond, which won't benefit a future request.  One minute is the default.
    private static final long EXPIRY_BUFFER_CHECK_MS = 60000L;

    // Keys to access the values in JSON.
    static final String ACCESS_TOKEN_KEY = "access_token";
    static final String REFRESH_TOKEN_KEY = "refresh_token";
    static final String EXPIRES_IN_KEY = "expires_in";
    private static final String EXPIRES_AT_MS_KEY = "expires_at_ms";


    private final String accessToken;
    private final String refreshToken;
    private final long expiryTimeMilliseconds;

    /**
     * Plain constructor.  Used when being pulled out of cache.
     *
     * @param accessToken            The current Access Token.
     * @param refreshToken           The current Refresh Token (if present).
     * @param expiryTimeMilliseconds The expiry time in milliseconds.  Used to compare for expiry.
     */
    public Assets(final String accessToken, final String refreshToken, final long expiryTimeMilliseconds) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiryTimeMilliseconds = expiryTimeMilliseconds;
    }

    /**
     * A new instance based on the JSON document from the OpenID Connect Provider.  This is typically used when a
     * new Access Token is obtained through Refresh or Authorization.
     *
     * @param tokenSet The JSON document of tokens.
     */
    public Assets(final JSONObject tokenSet) {
        this.accessToken = tokenSet.getString(Assets.ACCESS_TOKEN_KEY);
        this.refreshToken = tokenSet.getString(Assets.REFRESH_TOKEN_KEY);

        final int expirySeconds = tokenSet.getInt(Assets.EXPIRES_IN_KEY);
        this.expiryTimeMilliseconds = System.currentTimeMillis() + (expirySeconds * 1000L);
    }

    @Override
    public String toString() {
        final JSONObject jsonObject = new JSONObject();

        jsonObject.put(Assets.ACCESS_TOKEN_KEY, accessToken);

        if (StringUtil.hasText(refreshToken)) {
            jsonObject.put(Assets.REFRESH_TOKEN_KEY, refreshToken);
        }

        jsonObject.put(Assets.EXPIRES_AT_MS_KEY, expiryTimeMilliseconds);

        return jsonObject.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Assets assets = (Assets) o;
        return expiryTimeMilliseconds == assets.expiryTimeMilliseconds
               && Objects.equals(accessToken, assets.accessToken)
               && Objects.equals(refreshToken, assets.refreshToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(accessToken, refreshToken, expiryTimeMilliseconds);
    }

    public String getAccessToken() {
        return this.accessToken;
    }

    public String getRefreshToken() {
        return this.refreshToken;
    }

    public long getExpiryTimeMilliseconds() {
        return this.expiryTimeMilliseconds;
    }

    /**
     * Determine whether this asset's expiry time has already come, or is about to.  Used to determine whether a
     * refresh should be attempted.
     * @return True if expiry time is in the past (or close to), false otherwise.
     */
    public boolean isAccessTokenExpired() {
        return this.expiryTimeMilliseconds < (System.currentTimeMillis() - Assets.EXPIRY_BUFFER_CHECK_MS);
    }
}
