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
package org.eclipse.keyple.card.calypso;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.card.ApduResponse;

/**
 * (package-private)<br>
 * Parses the ChangeKey response.
 *
 * @since 2.0
 */
final class CardChangeKeyParser extends AbstractCardResponseParser {
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties(
            "Lc value not supported (not 04h, 10h, 18h, 20h).",
            CalypsoCardIllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties("Transaction Counter is 0.", CalypsoCardTerminatedException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (Get Challenge not done: challenge unavailable).",
            CalypsoCardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (a session is open or DF is invalidated).",
            CalypsoCardAccessForbiddenException.class));
    m.put(
        0x6988,
        new StatusProperties("Incorrect Cryptogram.", CalypsoCardSecurityDataException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Decrypted message incorrect (key algorithm not supported, incorrect padding, etc.).",
            CalypsoCardSecurityDataException.class));
    m.put(
        0x6A87,
        new StatusProperties(
            "Lc not compatible with P2.", CalypsoCardIllegalParameterException.class));
    m.put(
        0x6B00,
        new StatusProperties("Incorrect P1, P2.", CalypsoCardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CardChangeKeyParser
   *
   * @param response the response from the card.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public CardChangeKeyParser(ApduResponse response, CardChangeKeyBuilder builder) {
    super(response, builder);
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
