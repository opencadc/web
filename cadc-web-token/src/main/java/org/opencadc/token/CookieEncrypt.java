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

import org.apache.commons.lang3.RandomStringUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

class CookieEncrypt {
    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    private final String algorithm;


    public CookieEncrypt() {
        this(CookieEncrypt.DEFAULT_CIPHER_ALGORITHM);
    }

    CookieEncrypt(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Encrypt the provided string value with the desired SecretKey.  To use the default SecretKey, then use a generated
     * #encrypt(String) method instead.
     *
     * @param value The value to encrypt.
     * @param secretKey  The SecretKey to use to decipher it later.
     * @throws GeneralSecurityException For Cipher exceptions.
     */
    EncryptedCookie encrypt(final String value, final Key secretKey) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(this.algorithm);
        final byte[] iv = CookieEncrypt.initializeInitializationVector(cipher.getBlockSize());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        final byte[] encryptedValue =
                Base64.getEncoder().encode(cipher.doFinal(value.getBytes(StandardCharsets.ISO_8859_1)));
        return new EncryptedCookie(encryptedValue, iv, secretKey);
    }

    /**
     * Encrypt the provided string value with a generated SecretKey.
     *
     * @param value The value to encrypt.
     * @throws GeneralSecurityException For Cipher exceptions.
     */
    public EncryptedCookie encrypt(final String value) throws GeneralSecurityException {
        return encrypt(value, generateAESKey());
    }

    private static byte[] initializeInitializationVector(final int blockSize) {
        final byte[] initializationVector = new byte[blockSize];
        final SecureRandom random = new SecureRandom();
        random.nextBytes(initializationVector);

        return initializationVector;
    }

    Key generateAESKey() throws NoSuchAlgorithmException {
        final String secretKeyString = RandomStringUtils.randomAlphanumeric(16);

        // Generate a Secret Key.
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(secretKeyString.getBytes(StandardCharsets.ISO_8859_1));

        final byte[] keyBytes = new byte[16];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);

        return new SecretKeySpec(keyBytes, "AES");
    }
}
