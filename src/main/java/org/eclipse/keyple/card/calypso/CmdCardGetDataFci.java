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
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.BerTlvUtil;
import org.eclipse.keyple.core.util.HexUtil;
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
final class CmdCardGetDataFci extends CardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardGetDataFci.class);

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6A88,
        new StatusProperties(
            "Data object not found (optional mode not available).", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardDataAccessException.class));
    m.put(0x6283, new StatusProperties("Successful execution, FCI request and DF is invalidated."));
    STATUS_TABLE = m;
  }

  /* BER-TLV tags definitions */
  private static final int TAG_DF_NAME = 0x84;
  private static final int TAG_APPLICATION_SERIAL_NUMBER = 0xC7;
  private static final int TAG_DISCRETIONARY_DATA = 0x53;

  /** attributes result of th FCI parsing */
  private boolean isDfInvalidated = false;

  private boolean isValidCalypsoFCI = false;

  private byte[] dfName = null;
  private byte[] applicationSN = null;
  private byte[] discretionaryData = null;

  /**
   * Instantiates a new CmdCardGetDataFci.
   *
   * @param calypsoCard The Calypso card.
   * @since 2.2.3
   */
  CmdCardGetDataFci(CalypsoCardAdapter calypsoCard) {
    super(CardCommandRef.GET_DATA, 0, calypsoCard);
    buildCommand(calypsoCard.getCardClass());
  }

  /**
   * Instantiates a new CmdCardGetDataFci.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @since 2.0.1
   */
  CmdCardGetDataFci(CalypsoCardClass calypsoCardClass) {
    super(CardCommandRef.GET_DATA, 0, null);
    buildCommand(calypsoCardClass);
  }

  /**
   * Builds the command.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   */
  private void buildCommand(CalypsoCardClass calypsoCardClass) {
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(),
                getCommandRef().getInstructionByte(),
                (byte) 0x00,
                (byte) 0x6F,
                null,
                (byte) 0x00)));
  }

  /**
   * {@inheritDoc}
   *
   * @return False
   * @since 2.0.1
   */
  @Override
  boolean isSessionBufferUsed() {
    return false;
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
   * @since 2.0.1
   */
  @Override
  void parseApduResponse(ApduResponseApi apduResponse) throws CardCommandException {
    super.parseApduResponse(apduResponse);

    Map<Integer, byte[]> tags;

    /* check the command status to determine if the DF has been invalidated */
    // CL-INV-STATUS.1
    if (getApduResponse().getStatusWord() == 0x6283) {
      logger.debug(
          "The response to the select application command status word indicates that the DF has been invalidated.");
      isDfInvalidated = true;
    }

    /* parse the raw data with the help of the TLV class */
    try {
      /* init TLV object with the raw data and extract the FCI Template */
      final byte[] responseData = getApduResponse().getDataOut();
      // CL-SEL-TLVDATA.1
      // CL-TLV-VAR.1
      // CL-TLV-ORDER.1
      tags = BerTlvUtil.parseSimple(responseData, true);

      dfName = tags.get(TAG_DF_NAME);
      if (dfName == null) {
        logger.error("DF name tag (84h) not found.");
        return;
      }
      if (dfName.length < 5 || dfName.length > 16) {
        logger.error("Invalid DF name length: {}. Should be between 5 and 16.", dfName.length);
        return;
      }
      if (logger.isDebugEnabled()) {
        logger.debug("DF name = {}", HexUtil.toHex(dfName));
      }

      applicationSN = tags.get(TAG_APPLICATION_SERIAL_NUMBER);
      if (applicationSN == null) {
        logger.error("Serial Number tag (C7h) not found.");
        return;
      }
      // CL-SEL-CSN.1
      if (applicationSN.length != 8) {
        logger.error(
            "Invalid application serial number length: {}. Should be 8.", applicationSN.length);
        return;
      }
      if (logger.isDebugEnabled()) {
        logger.debug("Application Serial Number = {}", HexUtil.toHex(applicationSN));
      }

      discretionaryData = tags.get(TAG_DISCRETIONARY_DATA);
      if (discretionaryData == null) {
        logger.error("Discretionary data tag (53h) not found.");
        return;
      }
      if (discretionaryData.length < 7) {
        logger.error("Invalid startup info length: {}. Should be >= 7.", discretionaryData.length);
        return;
      }
      if (logger.isDebugEnabled()) {
        logger.debug("Discretionary Data = {}", HexUtil.toHex(discretionaryData));
      }

      /* all 3 main fields were retrieved */
      isValidCalypsoFCI = true;

    } catch (Exception e) {
      /* Silently ignore problems decoding TLV structure. Just log. */
      logger.debug("Error while parsing the FCI BER-TLV data structure ({})", e.getMessage());
    }

    getCalypsoCard().initializeWithFci(this);
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
