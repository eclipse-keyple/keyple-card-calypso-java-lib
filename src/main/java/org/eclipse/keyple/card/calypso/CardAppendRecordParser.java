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

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.card.ApduResponseApi;

/**
 * (package-private)<br>
 * Parses the Update records response.
 *
 * @since 2.0.0
 */
final class CardAppendRecordParser extends AbstractCardResponseParser {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardIllegalParameterException.class));
    m.put(0x6700, new StatusProperties("Lc value not supported.", CardDataAccessException.class));
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session.", CardSessionBufferOverflowException.class));
    m.put(
        0x6981,
        new StatusProperties("The current EF is not a Cyclic EF.", CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (no session, wrong key).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, DF is invalidated, etc..).",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Command not allowed (no current EF).", CardDataAccessException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
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

  /**
   * Instantiates a new CardAppendRecordParser.
   *
   * @param response the response from the card.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0.0
   */
  public CardAppendRecordParser(ApduResponseApi response, CardAppendRecordBuilder builder) {
    super(response, builder);
  }
}
