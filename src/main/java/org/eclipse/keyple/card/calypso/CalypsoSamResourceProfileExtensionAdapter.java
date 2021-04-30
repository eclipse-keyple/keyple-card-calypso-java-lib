/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://www.calypsonet-asso.org/
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

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.eclipse.keyple.card.calypso.sam.CalypsoSamResourceProfileExtension;
import org.eclipse.keyple.card.calypso.sam.SamRevision;
import org.eclipse.keyple.core.card.ProxyReader;
import org.eclipse.keyple.core.card.spi.CardResourceProfileExtensionSpi;
import org.eclipse.keyple.core.card.spi.SmartCardSpi;
import org.eclipse.keyple.core.service.CardSelectionServiceFactory;
import org.eclipse.keyple.core.service.Reader;
import org.eclipse.keyple.core.service.selection.CardSelectionResult;
import org.eclipse.keyple.core.service.selection.CardSelectionService;
import org.eclipse.keyple.core.service.selection.CardSelector;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Implementation of {@link CalypsoSamResourceProfileExtension}.
 *
 * @since 2.0
 */
class CalypsoSamResourceProfileExtensionAdapter
    implements CalypsoSamResourceProfileExtension, CardResourceProfileExtensionSpi {
  private static final Logger logger =
      LoggerFactory.getLogger(CalypsoSamResourceProfileExtensionAdapter.class);

  private SamRevision samRevision;
  private String samSerialNumberRegex;
  private String samUnlockData;

  /**
   * (package-private)<br>
   *
   * @since 2.0
   */
  CalypsoSamResourceProfileExtensionAdapter() {}

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoSamResourceProfileExtension setSamRevision(SamRevision samRevision) {

    Assert.getInstance().notNull(samRevision, "samRevision");

    if (this.samRevision != null) {
      throw new IllegalStateException("SAM revision has already been set.");
    }

    this.samRevision = samRevision;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoSamResourceProfileExtension setSamSerialNumberRegex(String samSerialNumberRegex) {

    Assert.getInstance().notEmpty(samSerialNumberRegex, "samSerialNumberRegex");

    if (this.samSerialNumberRegex != null) {
      throw new IllegalStateException("SAM serial number regex has already been set.");
    }

    try {
      Pattern.compile(samSerialNumberRegex);
    } catch (PatternSyntaxException exception) {
      throw new IllegalArgumentException("Invalid regular expression: " + samSerialNumberRegex);
    }

    this.samSerialNumberRegex = samSerialNumberRegex;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoSamResourceProfileExtension setSamUnlockData(String samUnlockData) {

    Assert.getInstance()
        .notEmpty(samUnlockData, "samUnlockData")
        .isTrue(samUnlockData.length() == 16 || samUnlockData.length() == 32, "length");

    if (this.samUnlockData != null) {
      throw new IllegalStateException("The unlock data has already been set.");
    }

    if (!ByteArrayUtil.isValidHexString(samUnlockData)) {
      throw new IllegalArgumentException("Invalid hexadecimal string.");
    }

    this.samUnlockData = samUnlockData;
    return this;
  }

  /**
   * (private) Build a regular expression to be used as ATR filter in the SAM selection process.
   *
   * <p>Both argument are optional and can be null.
   *
   * @param samRevision The target SAM revision.
   * @param samSerialNumberRegex A regular expression matching the SAM serial number.
   * @return A not empty string containing a regular
   */
  private String buildAtrRegex(SamRevision samRevision, String samSerialNumberRegex) {
    String atrRegex;
    String snRegex;
    /* check if serialNumber is defined */
    if (samSerialNumberRegex == null || samSerialNumberRegex.isEmpty()) {
      /* match all serial numbers */
      snRegex = ".{8}";
    } else {
      /* match the provided serial number (could be a regex substring) */
      snRegex = samSerialNumberRegex;
    }
    /*
     * build the final Atr regex according to the SAM subtype and serial number if any.
     *
     * The header is starting with 3B, its total length is 4 or 6 bytes (8 or 10 hex digits)
     */
    if (samRevision != null) {
      switch (samRevision) {
        case C1:
        case S1D:
        case S1E:
          atrRegex =
              "3B(.{6}|.{10})805A..80"
                  + samRevision.getApplicationTypeMask()
                  + "20.{4}"
                  + snRegex
                  + "829000";
          break;
        default:
          throw new IllegalArgumentException("Unknown SAM subtype.");
      }
    } else {
      /* match any ATR */
      atrRegex = ".*";
    }
    return atrRegex;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SmartCardSpi matches(ProxyReader reader) {

    if (!((Reader) reader).isCardPresent()) {
      return null;
    }

    CardSelector samCardSelector =
        CardSelector.builder()
            .filterByAtr(buildAtrRegex(samRevision, samSerialNumberRegex))
            .build();

    CardSelectionService samSelectionService = CardSelectionServiceFactory.getService();

    SamCardSelection samCardSelection = new SamCardSelectionAdapter(samCardSelector);

    // prepare the UNLOCK command if unlock data has been defined
    if (samUnlockData != null) {
      samCardSelection.prepareUnlock(samRevision, ByteArrayUtil.fromHex(samUnlockData));
    }

    samSelectionService.prepareSelection(samCardSelection);
    CardSelectionResult samCardSelectionResult = null;
    try {
      samCardSelectionResult = samSelectionService.processCardSelectionScenario((Reader) reader);
    } catch (Exception e) {
      logger.warn("An exception occurred while selecting the SAM: '{}'.", e.getMessage(), e);
    }

    if (samCardSelectionResult != null && samCardSelectionResult.hasActiveSelection()) {
      return (SmartCardSpi) samCardSelectionResult.getActiveSmartCard();
    }

    return null;
  }
}
