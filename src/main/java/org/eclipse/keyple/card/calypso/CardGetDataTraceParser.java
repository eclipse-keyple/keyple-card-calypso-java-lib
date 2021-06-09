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
 * Parses the Get Data command response.
 *
 * <p>Provides getter methods for all relevant information.
 *
 * @since 2.0
 */
final class CardGetDataTraceParser extends AbstractCardResponseParser {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
    m.put(
        0x6A88,
        new StatusProperties(
            "Data object not found (optional mode not available).", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties(
            "P1 or P2 value not supported (<>004fh, 0062h, 006Fh, 00C0h, 00D0h, 0185h and 5F52h, according to "
                + "available optional modes).",
            CardIllegalParameterException.class));
    m.put(
        0x6283,
        new StatusProperties("Successful execution, FCI request and DF is invalidated.", null));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CardGetDataTraceParser from the ApduResponseApi to a selection application
   * command.
   *
   * @param response the Traceability Data response from Get Data APDU command.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public CardGetDataTraceParser(ApduResponseApi response, CardGetDataTraceBuilder builder) {
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
