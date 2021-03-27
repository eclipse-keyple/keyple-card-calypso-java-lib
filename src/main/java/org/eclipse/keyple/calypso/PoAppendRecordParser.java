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
package org.eclipse.keyple.calypso;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.card.ApduResponse;

/**
 * (package-private)<br>
 * Parses the Update records response.
 *
 * @since 2.0
 */
final class PoAppendRecordParser extends AbstractPoResponseParser {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
    m.put(
        0x6B00,
        new StatusProperties(
            "P1 or P2 value not supported.", CalypsoPoIllegalParameterException.class));
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CalypsoPoDataAccessException.class));
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session.", CalypsoPoSessionBufferOverflowException.class));
    m.put(
        0x6981,
        new StatusProperties(
            "The current EF is not a Cyclic EF.", CalypsoPoDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (no session, wrong key).",
            CalypsoPoSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, DF is invalidated, etc..).",
            CalypsoPoAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Command not allowed (no current EF).", CalypsoPoDataAccessException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CalypsoPoDataAccessException.class));
    STATUS_TABLE = m;
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

  /**
   * Instantiates a new PoAppendRecordParser.
   *
   * @param response the response from the PO.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public PoAppendRecordParser(ApduResponse response, PoAppendRecordBuilder builder) {
    super(response, builder);
  }
}
