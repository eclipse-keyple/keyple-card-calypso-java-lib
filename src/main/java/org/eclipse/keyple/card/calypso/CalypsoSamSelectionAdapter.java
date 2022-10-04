/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.sam.CalypsoSamSelection;
import org.calypsonet.terminal.calypso.transaction.InconsistentDataException;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardSelectionResponseApi;
import org.calypsonet.terminal.card.spi.*;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Implementation of {@link CalypsoSamSelection}.
 *
 * <p>If not specified, the SAM product type used for unlocking is {@link
 * org.calypsonet.terminal.calypso.sam.CalypsoSam.ProductType#SAM_C1}.
 *
 * @since 2.0.0
 */
class CalypsoSamSelectionAdapter implements CalypsoSamSelection, CardSelectionSpi {

  private static final Logger logger = LoggerFactory.getLogger(CalypsoSamSelectionAdapter.class);
  private static final int SW_NOT_LOCKED = 0x6985;
  private final CardSelectorAdapter samCardSelector;
  private CalypsoSam.ProductType productType;
  private String serialNumberRegex;
  private CmdSamUnlock unlockCommand;

  /**
   * (package-private)<br>
   * Creates a {@link CalypsoSamSelection}.
   *
   * @since 2.0.0
   */
  CalypsoSamSelectionAdapter() {
    samCardSelector = new CardSelectorAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSelectionRequestSpi getCardSelectionRequest() {

    samCardSelector.filterByPowerOnData(buildAtrRegex(productType, serialNumberRegex));

    // prepare the UNLOCK command if unlock data has been defined
    if (unlockCommand != null) {
      List<ApduRequestSpi> cardSelectionApduRequests = new ArrayList<ApduRequestSpi>();
      cardSelectionApduRequests.add(
          unlockCommand.getApduRequest().addSuccessfulStatusWord(SW_NOT_LOCKED));
      return new CardSelectionRequestAdapter(
          samCardSelector, new CardRequestAdapter(cardSelectionApduRequests, false));
    } else {
      return new CardSelectionRequestAdapter(samCardSelector, null);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public SmartCardSpi parse(CardSelectionResponseApi cardSelectionResponse) throws ParseException {

    if (unlockCommand != null) {
      // an unlock command has been requested
      if (cardSelectionResponse.getCardResponse() == null
          || cardSelectionResponse.getCardResponse().getApduResponses().isEmpty()) {
        throw new InconsistentDataException("Mismatch in the number of requests/responses");
      }
      ApduResponseApi apduResponse =
          cardSelectionResponse.getCardResponse().getApduResponses().get(0);
      // check the SAM response to the unlock command
      try {
        unlockCommand.setApduResponse(apduResponse).checkStatus();
      } catch (CalypsoSamAccessForbiddenException e) {
        logger.warn("SAM not locked or already unlocked");
      } catch (CalypsoSamCommandException e) {
        throw new ParseException("An exception occurred while parse the SAM responses.", e);
      }
    }

    return new CalypsoSamAdapter(cardSelectionResponse);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoSamSelection filterByProductType(CalypsoSam.ProductType productType) {

    Assert.getInstance().notNull(productType, "productType");

    this.productType = productType;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoSamSelection filterBySerialNumber(String serialNumberRegex) {

    Assert.getInstance().notNull(serialNumberRegex, "serialNumberRegex");

    try {
      Pattern.compile(serialNumberRegex);
    } catch (PatternSyntaxException exception) {
      throw new IllegalArgumentException(
          String.format("Invalid regular expression: '%s'.", serialNumberRegex));
    }

    this.serialNumberRegex = serialNumberRegex;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoSamSelection setUnlockData(String unlockData) {
    Assert.getInstance()
        .notEmpty(unlockData, "unlockData")
        .isTrue(
            unlockData.length() == 16 || unlockData.length() == 32,
            "unlock data length == 16 or 32")
        .isHexString(unlockData, "unlockData");
    this.unlockCommand = new CmdSamUnlock(productType, HexUtil.toByteArray(unlockData));
    return this;
  }

  /**
   * (private) Build a regular expression to be used as ATR filter in the SAM selection process.
   *
   * <p>Both argument are optional and can be null.
   *
   * @param productType The target SAM product type.
   * @param samSerialNumberRegex A regular expression matching the SAM serial number.
   * @return A not empty string containing a regular
   */
  private String buildAtrRegex(CalypsoSam.ProductType productType, String samSerialNumberRegex) {
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
    String applicationTypeMask;
    if (productType != null) {
      switch (productType) {
        case SAM_C1:
        case HSM_C1:
          applicationTypeMask = "C1";
          break;
        case SAM_S1DX:
          applicationTypeMask = "D?";
          break;
        case SAM_S1E1:
          applicationTypeMask = "E1";
          break;
        case CSAM_F:
          // TODO Check what is the expected mask here
          applicationTypeMask = "??";
          break;
        default:
          throw new IllegalArgumentException("Unknown SAM subtype.");
      }
      atrRegex = "3B(.{6}|.{10})805A..80" + applicationTypeMask + ".{6}" + snRegex + "829000";
    } else {
      /* match any ATR */
      atrRegex = ".*";
    }
    return atrRegex;
  }
}
