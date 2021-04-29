/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://www.calypsonet-asso.org/
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
 * Parses the Rehabilitate response.
 *
 * @since 2.0
 */
final class CardRehabilitateParser extends AbstractCardResponseParser {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session.", CalypsoCardSessionBufferOverflowException.class));
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CalypsoCardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (no session, wrong key).",
            CalypsoCardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (DF context is invalid).",
            CalypsoCardAccessForbiddenException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CardRehabilitateParser.
   *
   * @param response the response from Rehabilitate APDU Command.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public CardRehabilitateParser(ApduResponse response, CardRehabilitateBuilder builder) {
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
