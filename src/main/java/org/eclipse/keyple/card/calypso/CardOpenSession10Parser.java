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
import org.eclipse.keyple.card.calypso.card.CardRevision;
import org.eclipse.keyple.core.card.ApduResponse;

/**
 * (package-private)<br>
 * Parses the Open session response from a card revision 1.0 .
 *
 * @since 2.0
 */
final class CardOpenSession10Parser extends AbstractCardOpenSessionParser {

  /**
   * Instantiates a new CardOpenSession10Parser from the response.
   *
   * @param response from CardOpenSession10Parser.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public CardOpenSession10Parser(ApduResponse response, CardOpenSession10Builder builder) {
    super(response, builder, CardRevision.REV1_0);
  }

  @Override
  SecureSession toSecureSession(byte[] apduResponseData) {
    return createSecureSession(apduResponseData);
  }

  public static SecureSession createSecureSession(byte[] apduResponseData) {
    boolean previousSessionRatified;

    /*
     * In rev 1.0 mode, the response to the Open Secure Session command is as follows:
     *
     * <p><code>CC CC CC CC [RR RR] [NN..NN]</code>
     *
     * <p>Where:
     *
     * <ul>
     *   <li><code>CC CC CC CC</code> = card challenge
     *   <li><code>RR RR</code> = ratification bytes (may be absent)
     *   <li><code>NN..NN</code> = record data (29 bytes)
     * </ul>
     *
     * Legal length values are:
     *
     * <ul>
     *   <li>4: ratified, 4-byte challenge, no data
     *   <li>33: ratified, 4-byte challenge, 29 bytes of data
     *   <li>6: not ratified (2 ratification bytes), 4-byte challenge, no data
     *   <li>35 not ratified (2 ratification bytes), 4-byte challenge, 29 bytes of data
     * </ul>
     */
    byte[] data;

    switch (apduResponseData.length) {
      case 4:
        previousSessionRatified = true;
        data = new byte[0];
        break;
      case 33:
        previousSessionRatified = true;
        data = Arrays.copyOfRange(apduResponseData, 4, 33);
        break;
      case 6:
        previousSessionRatified = false;
        data = new byte[0];
        break;
      case 35:
        previousSessionRatified = false;
        data = Arrays.copyOfRange(apduResponseData, 6, 35);
        break;
      default:
        throw new IllegalStateException(
            "Bad response length to Open Secure Session: " + apduResponseData.length);
    }

    /* KVC doesn't exist and is set to null for this type of card */
    return new SecureSession(
        Arrays.copyOfRange(apduResponseData, 0, 3),
        Arrays.copyOfRange(apduResponseData, 3, 4),
        previousSessionRatified,
        false,
        null,
        data,
        apduResponseData);
  }
}
