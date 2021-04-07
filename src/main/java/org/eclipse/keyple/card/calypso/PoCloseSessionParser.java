/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.card.calypso;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.card.ApduResponse;

/**
 * (package-private)<br>
 * Parses the Close Secure Session response.
 *
 * @since 2.0
 */
final class PoCloseSessionParser extends AbstractPoResponseParser {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties(
            "Lc signatureLo not supported (e.g. Lc=4 with a Revision 3.2 mode for Open Secure Session).",
            CalypsoPoIllegalParameterException.class));
    m.put(
        0x6B00,
        new StatusProperties(
            "P1 or P2 signatureLo not supported.", CalypsoPoIllegalParameterException.class));
    m.put(
        0x6988,
        new StatusProperties("incorrect signatureLo.", CalypsoPoSecurityDataException.class));
    m.put(
        0x6985,
        new StatusProperties("No session was opened.", CalypsoPoAccessForbiddenException.class));
    STATUS_TABLE = m;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  protected Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /** The signatureLo. */
  private final byte[] signatureLo;

  /** The postponed data. */
  private final byte[] postponedData;

  /**
   * Instantiates a new PoCloseSessionParser from the response.
   *
   * @param response from PoCloseSessionBuilder.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public PoCloseSessionParser(ApduResponse response, PoCloseSessionBuilder builder) {
    super(response, builder);
    byte[] responseData = response.getDataOut();
    if (responseData.length == 8) {
      signatureLo = Arrays.copyOfRange(responseData, 4, 8);
      postponedData = Arrays.copyOfRange(responseData, 1, 4);
    } else if (responseData.length == 4) {
      signatureLo = Arrays.copyOfRange(responseData, 0, 4);
      postponedData = new byte[0];
    } else {
      throw new IllegalArgumentException(
          "Unexpected length in response to CloseSecureSession command: " + responseData.length);
    }
  }

  public byte[] getSignatureLo() {
    return signatureLo;
  }

  public byte[] getPostponedData() {
    return postponedData;
  }
}
