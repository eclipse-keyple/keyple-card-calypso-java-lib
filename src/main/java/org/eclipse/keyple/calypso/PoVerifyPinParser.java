/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.calypso;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.card.ApduResponse;

/**
 * (package-private)<br>
 * Parses the Verify PIN response.
 *
 * @since 2.0
 */
final class PoVerifyPinParser extends AbstractPoResponseParser {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties(
            "Lc value not supported (only 00h, 04h or 08h are supported).",
            CalypsoPoIllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties("Transaction Counter is 0.", CalypsoPoTerminatedException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (Get Challenge not done: challenge unavailable).",
            CalypsoPoSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (a session is open or DF is invalidated).",
            CalypsoPoAccessForbiddenException.class));
    m.put(
        0x63C1,
        new StatusProperties("Incorrect PIN (1 attempt remaining).", CalypsoPoPinException.class));
    m.put(
        0x63C2,
        new StatusProperties("Incorrect PIN (2 attempt remaining).", CalypsoPoPinException.class));
    m.put(
        0x6983,
        new StatusProperties(
            "Presentation rejected (PIN is blocked).", CalypsoPoPinException.class));
    m.put(
        0x6D00,
        new StatusProperties(
            "PIN function not present.", CalypsoPoIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new PoVerifyPinParser
   *
   * @param response the response from the PO.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public PoVerifyPinParser(ApduResponse response, PoVerifyPinBuilder builder) {
    super(response, builder);
  }

  /**
   * Determine the value of the attempt counter from the status word
   *
   * @return the remaining attempt counter value (0, 1, 2 or 3)
   * @since 2.0
   */
  public int getRemainingAttemptCounter() {
    int attemptCounter;
    switch (response.getStatusCode()) {
      case 0x6983:
        attemptCounter = 0;
        break;
      case 0x63C1:
        attemptCounter = 1;
        break;
      case 0x63C2:
        attemptCounter = 2;
        break;
      case 0x9000:
        attemptCounter = 3;
        break;
      default:
        throw new IllegalStateException(
            "Incorrect status word: " + String.format("0x%04X", response.getStatusCode()));
    }
    return attemptCounter;
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
}
