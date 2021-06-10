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
import org.calypsonet.terminal.card.ApduResponseApi;

/**
 * (package-private)<br>
 * Parses the Open session response from a card revision 3.X.
 *
 * @since 2.0
 */
final class CardOpenSession3Parser extends AbstractCardOpenSessionParser {

  private static boolean isExtendedModeSupported = false;

  /**
   * Instantiates a new CardOpenSession3Parser from the response.
   *
   * @param response from CardOpenSession3Parser.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public CardOpenSession3Parser(ApduResponseApi response, CardOpenSession3Builder builder) {
    super(response, builder);
    isExtendedModeSupported = builder.isIsExtendedModeSupported();
  }

  @Override
  SecureSession toSecureSession(byte[] apduResponseData) {
    boolean previousSessionRatified;
    boolean manageSecureSessionAuthorized;
    int offset;

    if (!isExtendedModeSupported) {
      offset = 0;
      previousSessionRatified = (apduResponseData[4] == (byte) 0x00);
      manageSecureSessionAuthorized = false;
    } else {
      offset = 4;
      previousSessionRatified = (apduResponseData[8] & 0x01) == (byte) 0x00;
      manageSecureSessionAuthorized = (apduResponseData[8] & 0x02) == (byte) 0x02;
    }

    byte kif = apduResponseData[5 + offset];
    byte kvc = apduResponseData[6 + offset];
    int dataLength = apduResponseData[7 + offset];
    byte[] data = Arrays.copyOfRange(apduResponseData, 8 + offset, 8 + offset + dataLength);

    return new SecureSession(
        Arrays.copyOfRange(apduResponseData, 0, 3),
        Arrays.copyOfRange(apduResponseData, 3, 4 + offset),
        previousSessionRatified,
        manageSecureSessionAuthorized,
        kif,
        kvc,
        data,
        apduResponseData);
  }
}
