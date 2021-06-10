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
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.sam.CalypsoSamSelection;
import org.calypsonet.terminal.calypso.transaction.DesynchronizedExchangesException;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardSelectionResponseApi;
import org.calypsonet.terminal.card.spi.*;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Implementation of {@link SamCardSelection}.
 *
 * <p>If not specified, the SAM product type used for unlocking is {@link
 * org.calypsonet.terminal.calypso.sam.CalypsoSam.ProductType#SAM_C1}.
 *
 * @since 2.0
 */
class CalypsoSamCardSelectionAdapter implements CalypsoSamSelection, CardSelectionSpi {
  private static final Logger logger =
      LoggerFactory.getLogger(CalypsoSamCardSelectionAdapter.class);
  private final CardSelectorAdapter samCardSelector;
  private final ArrayList<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>>
      commandBuilders;
  private CalypsoSam.ProductType productType;
  private String serialNumberRegex;
  private String unlockData;

  /**
   * (package-private)<br>
   * Creates a {@link SamCardSelection}.
   *
   * @since 2.0
   */
  CalypsoSamCardSelectionAdapter() {
    samCardSelector = new CardSelectorAdapter();
    productType = CalypsoSam.ProductType.SAM_C1;
    this.commandBuilders =
        new ArrayList<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>>();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSelectionRequestSpi getCardSelectionRequest() {
    List<ApduRequestSpi> cardSelectionApduRequests = new ArrayList<ApduRequestSpi>();

    // prepare the UNLOCK command if unlock data has been defined
    if (unlockData != null) {
      commandBuilders.add(new SamUnlockBuilder(productType, ByteArrayUtil.fromHex(unlockData)));
      for (AbstractSamCommandBuilder<? extends AbstractSamResponseParser> commandBuilder :
          commandBuilders) {
        cardSelectionApduRequests.add(commandBuilder.getApduRequest());
      }
    }

    samCardSelector.filterByPowerOnData(buildAtrRegex(productType, serialNumberRegex));

    if (!cardSelectionApduRequests.isEmpty()) {
      return new CardSelectionRequestAdapter(
          samCardSelector, new CardRequestAdapter(cardSelectionApduRequests, false));
    } else {
      return new CardSelectionRequestAdapter(samCardSelector, null);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SmartCardSpi parse(CardSelectionResponseApi cardSelectionResponse) {

    if (commandBuilders.size() == 1) {
      // an unlock command has been requested
      List<ApduResponseApi> apduResponses =
          cardSelectionResponse.getCardResponse().getApduResponses();
      if (apduResponses == null) {
        throw new DesynchronizedExchangesException("Mismatch in the number of requests/responses");
      }
      // check the SAM response to the unlock command
      try {
        commandBuilders.get(0).createResponseParser(apduResponses.get(0)).checkStatus();
      } catch (CalypsoSamCommandException e) {
        // TODO check what to do here!
        logger.error("An exception occurred while parse the SAM responses: {}", e.getMessage());
      }
    }

    return new CalypsoSamAdapter(cardSelectionResponse);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoSamSelection filterByProductType(CalypsoSam.ProductType productType) {
    this.productType = productType;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoSamSelection filterBySerialNumber(String serialNumberRegex) {
    this.serialNumberRegex = serialNumberRegex;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoSamSelection setUnlockData(String unlockData) {
    Assert.getInstance()
        .notEmpty(unlockData, "unlockData")
        .isTrue(unlockData.length() == 16 || unlockData.length() == 32, "length");

    if (!ByteArrayUtil.isValidHexString(unlockData)) {
      throw new IllegalArgumentException("Invalid hexadecimal string.");
    }

    this.unlockData = unlockData;
    return this;
  }

  /**
   * (private) Build a regular expression to be used as ATR filter in the SAM selection process.
   *
   * <p>Both argument are optional and can be null.
   *
   * @param productType The target SAM revision.
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
          applicationTypeMask = "C1";
          break;
        case SAM_S1Dx:
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
      atrRegex = "3B(.{6}|.{10})805A..80" + applicationTypeMask + "20.{4}" + snRegex + "829000";
    } else {
      /* match any ATR */
      atrRegex = ".*";
    }
    return atrRegex;
  }
}
