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
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.card.calypso.card.CardRevision;

/**
 * (package-private)<br>
 * Parses the Open session response from a card revision 3.1.
 *
 * @since 2.0
 */
final class CardOpenSession31Parser extends AbstractCardOpenSessionParser {

  /**
   * Instantiates a new CardOpenSession31Parser from the response.
   *
   * @param response from CardOpenSession31Parser.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public CardOpenSession31Parser(ApduResponseApi response, CardOpenSession31Builder builder) {
    super(response, builder, CardRevision.REV3_1);
  }

  @Override
  SecureSession toSecureSession(byte[] apduResponseData) {
    boolean previousSessionRatified = (apduResponseData[4] == (byte) 0x00);
    boolean manageSecureSessionAuthorized = false;

    byte kif = apduResponseData[5];
    byte kvc = apduResponseData[6];
    int dataLength = apduResponseData[7];
    byte[] data = Arrays.copyOfRange(apduResponseData, 8, 8 + dataLength);

    return new SecureSession(
        Arrays.copyOfRange(apduResponseData, 0, 3),
        Arrays.copyOfRange(apduResponseData, 3, 4),
        previousSessionRatified,
        manageSecureSessionAuthorized,
        kif,
        kvc,
        data,
        apduResponseData);
  }
}
