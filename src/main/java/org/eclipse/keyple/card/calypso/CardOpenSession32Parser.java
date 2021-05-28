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
 * Parses the Open session response from a card revision 3.2 .
 *
 * @since 2.0
 */
final class CardOpenSession32Parser extends AbstractCardOpenSessionParser {

  /**
   * Instantiates a new CardOpenSession32Parser from the response.
   *
   * @param response from CardOpenSession32Parser.
   * @param builder the reference to the builder that created this parser.
   */
  public CardOpenSession32Parser(ApduResponseApi response, CardOpenSession32Builder builder) {
    super(response, builder, CardRevision.REV3_2);
  }

  /**
   * Method to get a Secure Session from the response in revision 3.2 mode.
   *
   * @param apduResponseData the apdu response data.
   * @return A SecureSession
   * @since 2.0
   */
  SecureSession toSecureSession(byte[] apduResponseData) {
    return createSecureSession(apduResponseData);
  }

  public static SecureSession createSecureSession(byte[] apduResponse) {

    byte flag = apduResponse[8];
    // ratification: if the bit 0 of flag is set then the previous session has been ratified
    boolean previousSessionRatified = (flag & 0x01) == (byte) 0x00;
    // secure session: if the bit 1 of flag is set then the secure session is authorized
    boolean manageSecureSessionAuthorized = (flag & 0x02) == (byte) 0x02;

    byte kif = apduResponse[9];
    byte kvc = apduResponse[10];
    int dataLength = apduResponse[11];
    byte[] data = Arrays.copyOfRange(apduResponse, 12, 12 + dataLength);

    return new SecureSession(
        Arrays.copyOfRange(apduResponse, 0, 3),
        Arrays.copyOfRange(apduResponse, 3, 8),
        previousSessionRatified,
        manageSecureSessionAuthorized,
        kif,
        kvc,
        data,
        apduResponse);
  }
}
