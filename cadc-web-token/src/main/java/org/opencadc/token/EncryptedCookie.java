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

import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

/**
 * The product of the encryption.  The values will all be included in the cookie value as a Base64 Encoded value.
 */
final class EncryptedCookie {
    final byte[] value;
    final byte[] initializationVector;
    final Key secretKey;

    /**
     * Create a new instance after encrypting a key.  The raw key value is in the encrypted value.
     * @param value        The encrypted key linked to the document in cache.
     * @param initializationVector  The InitializationVector value used in the encryption.
     * @param secretKey             The Secret Key value used in the encryption.
     * @see CookieEncrypt
     */
    public EncryptedCookie(byte[] value, byte[] initializationVector, Key secretKey) {
        this.value = value;
        this.initializationVector = initializationVector;
        this.secretKey = secretKey;
    }


    /**
     * Parse out the metadata from the given String input.  This is used when a cookie is received.
     * @param input The String value from a cookie.
     */
    public EncryptedCookie(final String input) {
        final byte[] decodedInput = Base64.getDecoder().decode(input.getBytes(StandardCharsets.ISO_8859_1));
        this.initializationVector = new byte[16];
        System.arraycopy(decodedInput, 0, this.initializationVector, 0, 16);

        final byte[] secretKeyBytes = new byte[16];
        System.arraycopy(decodedInput, 16, secretKeyBytes, 0, 16);
        this.secretKey = new SecretKeySpec(secretKeyBytes, "AES");

        final int startPos = initializationVector.length + secretKeyBytes.length;
        this.value = new byte[decodedInput.length - startPos];
        System.arraycopy(decodedInput, startPos, this.value, 0, value.length);
    }

    public byte[] getValue() {
        return value;
    }

    public byte[] getInitializationVector() {
        return initializationVector;
    }

    public Key getSecretKey() {
        return secretKey;
    }

    /**
     * Obtain the encoded cookie value as it should be when written out.
     * @return  A byte array of Base64 Encoded values in this instance.  Never null.
     * @throws IOException  For writing data problems.
     */
    public byte[] marshall() throws IOException {
        try (final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            byteArrayOutputStream.write(this.initializationVector);
            byteArrayOutputStream.write(this.secretKey.getEncoded());
            byteArrayOutputStream.write(this.value);

            byteArrayOutputStream.flush();

            return Base64.getEncoder().encode(byteArrayOutputStream.toByteArray());
        }
    }
}
