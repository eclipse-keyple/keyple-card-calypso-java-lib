/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://calypsonet.org/
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
import org.calypsonet.terminal.card.ApduResponseApi;

/**
 * (package-private)<br>
 * Parses the Close Secure Session response.
 *
 * @since 2.0.0
 */
final class CardCloseSessionParser extends AbstractCardResponseParser {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties(
            "Lc signatureLo not supported (e.g. Lc=4 with a Revision 3.2 mode for Open Secure Session).",
            CardIllegalParameterException.class));
    m.put(
        0x6B00,
        new StatusProperties(
            "P1 or P2 signatureLo not supported.", CardIllegalParameterException.class));
    m.put(0x6988, new StatusProperties("incorrect signatureLo.", CardSecurityDataException.class));
    m.put(
        0x6985, new StatusProperties("No session was opened.", CardAccessForbiddenException.class));
    STATUS_TABLE = m;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
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
   * Instantiates a new CardCloseSessionParser from the response.
   *
   * <p>Checks the card response length; the admissible lengths are 0, 4 or 8 bytes.
   *
   * @param response from CardCloseSessionBuilder.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0.0
   */
  public CardCloseSessionParser(ApduResponseApi response, CardCloseSessionBuilder builder) {
    super(response, builder);
    byte[] responseData = response.getDataOut();
    if (builder.getCalypsoCard().isExtendedModeSupported()) {
      // 8-byte signature
      if (responseData.length == 8) {
        // signature only
        signatureLo = Arrays.copyOfRange(responseData, 0, 8);
        postponedData = new byte[0];
      } else if (responseData.length == 12) {
        // signature + 3 postponed bytes (+1)
        signatureLo = Arrays.copyOfRange(responseData, 4, 12);
        postponedData = Arrays.copyOfRange(responseData, 1, 4);
      } else if (responseData.length == 15) {
        // signature + 6 postponed bytes (+1)
        signatureLo = Arrays.copyOfRange(responseData, 7, 15);
        postponedData = Arrays.copyOfRange(responseData, 1, 7);
      } else {
        if (responseData.length != 0) {
          throw new IllegalArgumentException(
              "Unexpected length in response to CloseSecureSession command: "
                  + responseData.length);
        }
        // session abort case
        signatureLo = new byte[0];
        postponedData = new byte[0];
      }
    } else {
      // 4-byte signature
      if (responseData.length == 4) {
        // signature only
        signatureLo = Arrays.copyOfRange(responseData, 0, 4);
        postponedData = new byte[0];
      } else if (responseData.length == 8) {
        // signature + 3 postponed bytes (+1)
        signatureLo = Arrays.copyOfRange(responseData, 4, 8);
        postponedData = Arrays.copyOfRange(responseData, 1, 4);
      } else if (responseData.length == 11) {
        // signature + 6 postponed bytes (+1)
        signatureLo = Arrays.copyOfRange(responseData, 7, 11);
        postponedData = Arrays.copyOfRange(responseData, 1, 7);
      } else {
        if (responseData.length != 0) {
          throw new IllegalArgumentException(
              "Unexpected length in response to CloseSecureSession command: "
                  + responseData.length);
        }
        // session abort case
        signatureLo = new byte[0];
        postponedData = new byte[0];
      }
    }
  }

  /**
   * Gets the low part of the session signature.
   *
   * @return A 4 or 8-byte array of bytes according to the extended mode availability.
   */
  public byte[] getSignatureLo() {
    return signatureLo;
  }

  /**
   * Gets the secure session postponed data (e.g. Sv Signature).
   *
   * @return A 0, 3 or 6-byte array of bytes according to presence of postponed data and the
   *     extended mode usage.
   */
  public byte[] getPostponedData() {
    return postponedData;
  }
}
