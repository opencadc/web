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

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import redis.clients.jedis.RedisClient;

/**
 * Default TokenStore implementation access to a cache. By default, this relies on a Redis instance and the Jedis Java
 * library.
 */
class RedisTokenStore implements TokenStore {
    private static final String ACCESS_TOKEN_FIELD = "accessToken";
    private static final String REFRESH_TOKEN_FIELD = "refreshToken";
    private static final String EXPIRES_AT_MS_TOKEN_FIELD = "expiresAtMS";

    private final URI redisURI;

    RedisTokenStore(final String url) {
        this.redisURI = URI.create(url);
    }

    private static Map<String, String> getPayload(final Assets assets) {
        final Map<String, String> payload = new HashMap<>();
        payload.put(RedisTokenStore.ACCESS_TOKEN_FIELD, assets.getAccessToken());
        payload.put(RedisTokenStore.REFRESH_TOKEN_FIELD, assets.getRefreshToken());
        payload.put(RedisTokenStore.EXPIRES_AT_MS_TOKEN_FIELD, Long.toString(assets.getExpiryTimeMilliseconds()));
        return payload;
    }

    /**
     * Insert a new Asset, then return the generated key. Use UUIDs to ensure uniqueness.
     *
     * @param assets The Assets to store.
     * @return String key, never null.
     */
    @Override
    public String put(final Assets assets) {
        final String assetKey = UUID.randomUUID().toString();
        this.put(assetKey, assets);
        return assetKey;
    }

    /**
     * Insert or update an Asset at the given key.
     *
     * @param assetsKey The key to store the Assets at.
     * @param assets The Assets to store.
     */
    @Override
    public void put(final String assetsKey, final Assets assets) {
        try (final RedisClient redisClient = RedisClient.create(this.redisURI)) {
            redisClient.hset(assetsKey, RedisTokenStore.getPayload(assets));
        }
    }

    /**
     * Obtain the Assets from the cache at the given key, or throw an Exception.
     *
     * @param assetsKey The key to look up.
     * @return The Assets document. Never null.
     * @throws NoSuchElementException If the given key returns nothing.
     */
    @Override
    public Assets get(final String assetsKey) {
        try (final RedisClient redisClient = RedisClient.create(this.redisURI)) {
            if (redisClient.exists(assetsKey)) {
                final Map<String, String> assetsHash = redisClient.hgetAll(assetsKey);
                return new Assets(
                        assetsHash.get(RedisTokenStore.ACCESS_TOKEN_FIELD),
                        assetsHash.get(RedisTokenStore.REFRESH_TOKEN_FIELD),
                        Long.parseLong(assetsHash.get(RedisTokenStore.EXPIRES_AT_MS_TOKEN_FIELD)));
            } else {
                throw new NoSuchElementException("No asset with key " + assetsKey);
            }
        }
    }
}
