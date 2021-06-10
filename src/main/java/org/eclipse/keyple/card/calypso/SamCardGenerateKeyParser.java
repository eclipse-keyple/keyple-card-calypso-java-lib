/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/
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
 * Parses the Card Generate Key response.
 *
 * @since 2.0
 */
final class SamCardGenerateKeyParser extends AbstractSamResponseParser {

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
        0x6A00,
        new StatusProperties("Incorrect P1 or P2", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect incoming data: unknown or incorrect format",
            CalypsoSamIncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: ciphering key or key to cipher not found",
            CalypsoSamDataAccessException.class));
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
   * Instantiates a new SamCardGenerateKeyParser.
   *
   * @param response from the SAM.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public SamCardGenerateKeyParser(ApduResponseApi response, SamCardGenerateKeyBuilder builder) {
    super(response, builder);
  }

  /**
   * Gets the 32 bytes of ciphered data.
   *
   * @return the ciphered data byte array or null if the operation failed
   * @since 2.0
   */
  public byte[] getCipheredData() {
    return isSuccessful() ? response.getDataOut() : null;
  }
}
