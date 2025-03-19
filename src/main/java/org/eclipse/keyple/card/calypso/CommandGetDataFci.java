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

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.BerTlvUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.card.ApduResponseApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the Get data APDU commands for the FCI tag.
 *
 * <p>In contact mode, this command can not be sent in a secure session because it would generate a
 * 6Cxx status and thus make calculation of the digest impossible.
 *
 * @since 2.0.1
 */
final class CommandGetDataFci extends Command {

  private static final Logger logger = LoggerFactory.getLogger(CommandGetDataFci.class);

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(
        0x6A88,
        new StatusProperties(
            "Data object not found (optional mode not available)", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported", CardDataAccessException.class));
    m.put(0x6283, new StatusProperties("Successful execution, FCI request and DF is invalidated"));
    STATUS_TABLE = m;
  }

  /* BER-TLV tags definitions */
  private static final int TAG_DF_NAME = 0x84;
  private static final int TAG_APPLICATION_SERIAL_NUMBER = 0xC7;
  private static final int TAG_DISCRETIONARY_DATA = 0x53;

  /** attributes result of th FCI parsing */
  private boolean isDfInvalidated;

  private boolean isValidCalypsoFCI;
  private byte[] dfName;
  private byte[] applicationSN;
  private byte[] discretionaryData;

  /**
   * Constructor.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @since 2.3.2
   */
  CommandGetDataFci(TransactionContextDto transactionContext, CommandContextDto commandContext) {
    super(CardCommandRef.GET_DATA, null, transactionContext, commandContext);
    byte cardClass =
        transactionContext.getCard() != null
            ? transactionContext.getCard().getCardClass().getValue()
            : CalypsoCardClass.ISO.getValue();

    // APDU Case 2 - always outside secure session
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cardClass,
                getCommandRef().getInstructionByte(),
                CalypsoCardConstant.TAG_FCI_FOR_CURRENT_DF_MSB,
                CalypsoCardConstant.TAG_FCI_FOR_CURRENT_DF_LSB,
                null,
                (byte) 0x00)));
    addSubName("FCI_FOR_CURRENT_DF");
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void finalizeRequest() {
    // NOP
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean isCryptoServiceRequiredToFinalizeRequest() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean synchronizeCryptoServiceBeforeCardProcessing() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The expected FCI structure of a Calypso card follows this scheme: <code>
   * T=6F L=XX (C)                FCI Template
   * T=84 L=XX (P)           DF Name
   * T=A5 L=22 (C)           FCI Proprietary Template
   * T=BF0C L=19 (C)    FCI Issuer Discretionary Data
   * T=C7 L=8 (P)  Application Serial Number
   * T=53 L=7 (P)  Discretionary Data (Startup Information)
   * </code>
   *
   * <p>The ApduResponseApi provided in argument is parsed according to the above expected
   * structure.
   *
   * <p>DF Name, Application Serial Number and Startup Information are extracted.
   *
   * <p>The 7-byte startup information field is also split into 7 private field made available
   * through dedicated getter methods.
   *
   * <p>All fields are pre-initialized to handle the case where the parsing fails.
   *
   * @since 2.3.2
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CardCommandException {
    super.setApduResponseAndCheckStatus(apduResponse);

    Map<Integer, byte[]> tags;

    /* check the command status to determine if the DF has been invalidated */
    // CL-INV-STATUS.1
    if (getApduResponse().getStatusWord() == 0x6283) {
      logger.debug("DF invalidated");
      isDfInvalidated = true;
    }

    /* parse the raw data with the help of the TLV class */
    try {
      /* init TLV object with the raw data and extract the FCI Template */
      byte[] responseData = getApduResponse().getDataOut();
      // CL-SEL-TLVDATA.1
      // CL-TLV-VAR.1
      // CL-TLV-ORDER.1
      tags = BerTlvUtil.parseSimple(responseData, true);

      dfName = tags.get(TAG_DF_NAME);
      if (dfName == null) {
        logger.error("DF name tag (84h) not found");
        return;
      }
      if (dfName.length < 5 || dfName.length > 16) {
        logger.error("Invalid DF name length {} (not in range [5..16])", dfName.length);
        return;
      }
      if (logger.isDebugEnabled()) {
        logger.debug("DF name: {}", HexUtil.toHex(dfName));
      }

      applicationSN = tags.get(TAG_APPLICATION_SERIAL_NUMBER);
      if (applicationSN == null) {
        logger.error("Serial number tag (C7h) not found");
        return;
      }
      // CL-SEL-CSN.1
      if (applicationSN.length != 8) {
        logger.error(
            "Invalid application serial number length {} (expected 8)", applicationSN.length);
        return;
      }
      if (logger.isDebugEnabled()) {
        logger.debug("Application serial number: {}h", HexUtil.toHex(applicationSN));
      }

      discretionaryData = tags.get(TAG_DISCRETIONARY_DATA);
      if (discretionaryData == null) {
        logger.error("Discretionary data tag (53h) not found");
        return;
      }
      if (discretionaryData.length < 7) {
        logger.error("Invalid startup info length {} (should be >= 7)", discretionaryData.length);
        return;
      }
      if (logger.isDebugEnabled()) {
        logger.debug("Discretionary data: {}", HexUtil.toHex(discretionaryData));
      }

      /* all 3 main fields were retrieved */
      isValidCalypsoFCI = true;

    } catch (Exception e) {
      /* Silently ignore problems decoding TLV structure. Just log. */
      logger.debug("Failed to parse FCI BER-TLV data structure: {}", e.getMessage());
    }

    getTransactionContext().getCard().initializeWithFci(this);
  }

  /**
   * Tells if the FCI is valid
   *
   * @return True if the FCI is valid, false if not
   * @since 2.0.1
   */
  boolean isValidCalypsoFCI() {
    return isValidCalypsoFCI;
  }

  /**
   * Gets the DF name
   *
   * @return An array of bytes
   * @since 2.0.1
   */
  byte[] getDfName() {
    return dfName;
  }

  /**
   * Gets the application serial number
   *
   * @return An array of bytes
   * @since 2.0.1
   */
  byte[] getApplicationSerialNumber() {
    return applicationSN;
  }

  /**
   * Gets the discretionary data
   *
   * @return An array of bytes
   * @since 2.0.1
   */
  byte[] getDiscretionaryData() {
    return discretionaryData;
  }

  /**
   * Tells if the DF is invalidated
   *
   * @return True if the DF is invalidated, false if not
   * @since 2.0.1
   */
  boolean isDfInvalidated() {
    return isDfInvalidated;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
