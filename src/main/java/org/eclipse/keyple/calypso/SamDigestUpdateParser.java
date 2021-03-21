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
 * Parses the Digest update response parser.
 *
 * @since 2.0
 */
final class SamDigestUpdateParser extends AbstractSamResponseParser {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamResponseParser.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied.", CalypsoSamAccessForbiddenException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect value in the incoming data: session in Rev.3.2 mode with encryption/decryption active and not enough data (less than 5 bytes for and odd occurrence or less than 2 bytes for an even occurrence).",
            CalypsoSamIncorrectInputDataException.class));
    m.put(
        0x6B00,
        new StatusProperties("Incorrect P1 or P2.", CalypsoSamIllegalParameterException.class));
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
   * Instantiates a new SamDigestUpdateParser.
   *
   * @param response the response.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public SamDigestUpdateParser(ApduResponse response, SamDigestUpdateBuilder builder) {
    super(response, builder);
  }
}
