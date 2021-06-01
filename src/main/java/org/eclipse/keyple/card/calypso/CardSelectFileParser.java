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

import static org.eclipse.keyple.core.util.bertlv.Tag.TagType.PRIMITIVE;

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.bertlv.TLV;
import org.eclipse.keyple.core.util.bertlv.Tag;

/**
 * (package-private)<br>
 * Parses the response to a Select File command.
 *
 * @since 2.0
 *     <p>The value of the Proprietary Information tag is extracted from the Select File response
 *     and made available using the corresponding getter.
 */
final class CardSelectFileParser extends AbstractCardResponseParser {
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties(
            "Lc value not supported.", CalypsoCardIllegalParameterException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CalypsoCardDataAccessException.class));
    m.put(0x6119, new StatusProperties("Correct execution (ISO7816 T=0).", null));
    STATUS_TABLE = m;
  }

  private byte[] proprietaryInformation;

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  protected Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /* Proprietary Information: context-specific class, primitive, tag number 5h => tag field 85h */
  private static final Tag TAG_PROPRIETARY_INFORMATION = new Tag(0x05, Tag.CONTEXT, PRIMITIVE, 1);

  /**
   * Instantiates a new CardSelectFileParser.
   *
   * @param response the response from the card.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public CardSelectFileParser(ApduResponseApi response, CardSelectFileBuilder builder) {
    super(response, builder);
    proprietaryInformation = null;
  }

  /**
   * @return The content of the proprietary information tag present in the response to the Select
   *     File command
   * @since 2.0
   */
  public byte[] getProprietaryInformation() {
    if (proprietaryInformation == null) {
      TLV tlv = new TLV(response.getDataOut());
      if (!tlv.parse(TAG_PROPRIETARY_INFORMATION, 0)) {
        throw new IllegalStateException("Proprietary information: tag not found.");
      }
      proprietaryInformation = tlv.getValue();
      Assert.getInstance().isEqual(proprietaryInformation.length, 23, "proprietaryInformation");
    }
    return proprietaryInformation;
  }
}
