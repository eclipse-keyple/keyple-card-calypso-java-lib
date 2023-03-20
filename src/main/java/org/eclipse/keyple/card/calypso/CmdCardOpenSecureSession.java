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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.transaction.UnauthorizedKeyException;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the Open Secure Session APDU command.
 *
 * @since 2.0.1
 */
final class CmdCardOpenSecureSession extends CardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardOpenSecureSession.class);
  private static final String EXTRA_INFO_FORMAT = "KEYINDEX:%d, SFI:%02Xh, REC:%d";
  private static final String PATTERN_1_BYTE_HEX = "%02Xh";

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CardIllegalParameterException.class));
    m.put(0x6900, new StatusProperties("Transaction Counter is 0", CardTerminatedException.class));
    m.put(
        0x6981,
        new StatusProperties(
            "Command forbidden (read requested and current EF is a Binary file).",
            CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (PIN code not presented, AES key forbidding the "
                + "compatibility mode, encryption required).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, Session already opened).",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Command not allowed (read requested and no current EF).",
            CardDataAccessException.class));
    m.put(0x6A81, new StatusProperties("Wrong key index.", CardIllegalParameterException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found (record index is above NumRec).", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties(
            "P1 or P2 value not supported (key index incorrect, wrong P2, extended mode not supported).",
            CardIllegalParameterException.class));
    m.put(0x61FF, new StatusProperties("Correct execution (ISO7816 T=0)."));
    m.put(
        0x6200,
        new StatusProperties(
            "Successful execution, with warning (Pre-Open variant, secure session not opened)."));
    STATUS_TABLE = m;
  }

  private final WriteAccessLevel writeAccessLevel;
  private final boolean isExtendedModeAllowed;
  private SymmetricCryptoSecuritySettingAdapter symmetricCryptoSecuritySetting;
  private transient boolean isPreOpenMode; // NOSONAR
  private transient byte[] preOpenDataOut; // NOSONAR
  private transient boolean isReadModeConfigured; // NOSONAR
  private int sfi;
  private int recordNumber;

  private transient boolean isPreviousSessionRatified; // NOSONAR
  private byte[] challengeTransactionCounter;
  private byte[] challengeRandomNumber;
  private Byte kif;
  private Byte kvc;
  private byte[] recordData;

  /**
   * Constructor.
   *
   * @param calypsoCard The Calypso card.
   * @param writeAccessLevel The write access level.
   * @param samChallenge The SAM challenge.
   * @param sfi The optional SFI of the file to read.
   * @param recordNumber The optional record number to read.
   * @param isExtendedModeAllowed True if the extended mode is allowed.
   * @since 2.0.1
   */
  CmdCardOpenSecureSession(
      CalypsoCardAdapter calypsoCard,
      WriteAccessLevel writeAccessLevel,
      byte[] samChallenge,
      int sfi,
      int recordNumber,
      boolean isExtendedModeAllowed) {

    super(CardCommandRef.OPEN_SECURE_SESSION, 0, calypsoCard, null, null);

    this.isExtendedModeAllowed = isExtendedModeAllowed;
    this.writeAccessLevel = writeAccessLevel;
    this.sfi = sfi;
    this.recordNumber = recordNumber;

    byte keyIndex = (byte) (writeAccessLevel.ordinal() + 1);
    switch (getCalypsoCard().getProductType()) {
      case PRIME_REVISION_1:
        createRev10(keyIndex, samChallenge);
        break;
      case PRIME_REVISION_2:
        createRev24(keyIndex, samChallenge);
        break;
      case PRIME_REVISION_3:
      case LIGHT:
      case BASIC:
        createRev3(keyIndex, samChallenge);
        break;
      default:
        throw new IllegalArgumentException(
            "Product type " + getCalypsoCard().getProductType() + " isn't supported");
    }
  }

  /**
   * Constructor for "pre-open" variant (to be used for card selection only).
   *
   * @param writeAccessLevel The write access level.
   * @since 2.3.3
   */
  CmdCardOpenSecureSession(WriteAccessLevel writeAccessLevel) {
    super(CardCommandRef.OPEN_SECURE_SESSION, 0, null, null, null);
    isExtendedModeAllowed = true;
    this.writeAccessLevel = writeAccessLevel;
    createRev3((byte) (writeAccessLevel.ordinal() + 1), new byte[0]); // with no SAM challenge
    if (logger.isDebugEnabled()) {
      addSubName("PREOPEN");
    }
  }

  /**
   * Partial constructor.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param symmetricCryptoSecuritySetting The symmetric crypto security settings to use.
   * @param writeAccessLevel The write access level.
   * @param isExtendedModeAllowed Is the extended mode allowed?
   * @since 2.3.2
   */
  CmdCardOpenSecureSession(
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      SymmetricCryptoSecuritySettingAdapter symmetricCryptoSecuritySetting,
      WriteAccessLevel writeAccessLevel,
      boolean isExtendedModeAllowed) {
    super(CardCommandRef.OPEN_SECURE_SESSION, 0, null, transactionContext, commandContext);
    this.writeAccessLevel = writeAccessLevel;
    this.symmetricCryptoSecuritySetting = symmetricCryptoSecuritySetting;
    this.isExtendedModeAllowed = isExtendedModeAllowed;
    preOpenDataOut = transactionContext.getCard().getPreOpenDataOut();
    isPreOpenMode = preOpenDataOut != null;
  }

  /**
   * Create Rev 3
   *
   * @param keyIndex the key index.
   * @param samChallenge the sam challenge returned by the SAM Get Challenge APDU command.
   * @throws IllegalArgumentException If the request is inconsistent
   */
  private void createRev3(byte keyIndex, byte[] samChallenge) {

    byte p1 = (byte) ((recordNumber * 8) + keyIndex);
    byte p2;
    byte[] dataIn;

    if (isExtendedModeAllowed) {
      p2 = (byte) ((sfi * 8) + 2);
      dataIn = new byte[samChallenge.length + 1];
      System.arraycopy(samChallenge, 0, dataIn, 1, samChallenge.length);
    } else {
      p2 = (byte) ((sfi * 8) + 1);
      dataIn = samChallenge;
    }

    /*
     * case 4: this command contains incoming and outgoing data. We define le = 0, the actual
     * length will be processed by the lower layers.
     */
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                CalypsoCardClass.ISO.getValue(),
                CardCommandRef.OPEN_SECURE_SESSION.getInstructionByte(),
                p1,
                p2,
                dataIn,
                (byte) 0)));

    if (logger.isDebugEnabled()) {
      String extraInfo = String.format(EXTRA_INFO_FORMAT, keyIndex, sfi, recordNumber);
      addSubName(extraInfo);
    }
  }

  /**
   * Create Rev 2.4
   *
   * @param keyIndex the key index.
   * @param samChallenge the sam challenge returned by the SAM Get Challenge APDU command.
   */
  private void createRev24(byte keyIndex, byte[] samChallenge) {
    byte p1 = (byte) (0x80 + (recordNumber * 8) + keyIndex);
    buildLegacyApduRequest(keyIndex, samChallenge, sfi, recordNumber, p1);
  }

  /**
   * Create Rev 1.0
   *
   * @param keyIndex the key index.
   * @param samChallenge the sam challenge returned by the SAM Get Challenge APDU command.
   */
  private void createRev10(byte keyIndex, byte[] samChallenge) {
    byte p1 = (byte) ((recordNumber * 8) + keyIndex);
    buildLegacyApduRequest(keyIndex, samChallenge, sfi, recordNumber, p1);
  }

  /**
   * Build legacy apdu request.
   *
   * @param keyIndex the key index.
   * @param samChallenge the sam challenge returned by the SAM Get Challenge APDU command.
   * @param sfi the sfi to select.
   * @param recordNumber the record number to read.
   * @param p1 P1.
   * @throws IllegalArgumentException If the request is inconsistent
   */
  private void buildLegacyApduRequest(
      byte keyIndex, byte[] samChallenge, int sfi, int recordNumber, byte p1) {

    byte p2 = (byte) (sfi * 8);
    /*
     * case 4: this command contains incoming and outgoing data. We define le = 0, the actual
     * length will be processed by the lower layers.
     */
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                CalypsoCardClass.LEGACY.getValue(),
                CardCommandRef.OPEN_SECURE_SESSION.getInstructionByte(),
                p1,
                p2,
                samChallenge,
                (byte) 0)));

    if (logger.isDebugEnabled()) {
      String extraInfo = String.format(EXTRA_INFO_FORMAT, keyIndex, sfi, recordNumber);
      addSubName(extraInfo);
    }
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
   * Configures the read mode.
   *
   * @param sfi The SFI to select.
   * @param recordNumber The number of the record to read.
   * @since 2.3.2
   */
  void configureReadMode(int sfi, int recordNumber) {
    this.sfi = sfi;
    this.recordNumber = recordNumber;
    isReadModeConfigured = true;
  }

  /**
   * @return "true" if the read mode is already configured.
   * @since 2.3.2
   */
  boolean isReadModeConfigured() {
    return isReadModeConfigured;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void finalizeRequest() {
    byte[] samChallenge;
    try {
      samChallenge =
          getTransactionContext()
              .getSymmetricCryptoTransactionManagerSpi()
              .initTerminalSecureSessionContext();
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }
    byte keyIndex = (byte) (writeAccessLevel.ordinal() + 1);
    switch (getTransactionContext().getCard().getProductType()) {
      case PRIME_REVISION_1:
        createRev10(keyIndex, samChallenge);
        break;
      case PRIME_REVISION_2:
        createRev24(keyIndex, samChallenge);
        break;
      case PRIME_REVISION_3:
      case LIGHT:
      case BASIC:
        createRev3(keyIndex, samChallenge);
        break;
      default:
        throw new IllegalArgumentException(
            "Product type "
                + getTransactionContext().getCard().getProductType()
                + " not supported");
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean isCryptoServiceRequiredToFinalizeRequest() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean synchronizeCryptoServiceBeforeCardProcessing() {
    if (!isPreOpenMode) {
      return false;
    }
    if (!isCryptoServiceSynchronized()) {
      parseRev3(preOpenDataOut);
      synchronizeCryptoService(preOpenDataOut);
    }
    return true;
  }

  /**
   * Synchronizes the crypto service.
   *
   * @param dataOut The APDU dataOut field.
   */
  private void synchronizeCryptoService(byte[] dataOut) {
    Byte computedKvc = computeKvc();
    Byte computedKif = computeKif(computedKvc);
    if (!symmetricCryptoSecuritySetting.isSessionKeyAuthorized(computedKif, computedKvc)) {
      throw new UnauthorizedKeyException(
          String.format(
              "Unauthorized key error: KIF=%s, KVC=%s",
              computedKif != null ? String.format(PATTERN_1_BYTE_HEX, computedKif) : null,
              computedKvc != null ? String.format(PATTERN_1_BYTE_HEX, computedKvc) : null));
    }
    try {
      getTransactionContext()
          .getSymmetricCryptoTransactionManagerSpi()
          .initTerminalSessionMac(dataOut, computedKif, computedKvc);
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }
    confirmCryptoServiceSuccessfullySynchronized();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CardCommandException {
    super.setApduResponseAndCheckStatus(apduResponse);
    CalypsoCardAdapter card = getTransactionContext().getCard();
    card.backupFiles();
    getTransactionContext().setSecureSessionOpen(true);
    byte[] dataOut = getApduResponse().getDataOut();
    switch (card.getProductType()) {
      case PRIME_REVISION_1:
        parseRev10(dataOut);
        break;
      case PRIME_REVISION_2:
        parseRev24(dataOut);
        break;
      default:
        parseRev3(dataOut);
    }
    // CL-CSS-INFORAT.1
    card.setDfRatified(isPreviousSessionRatified);
    // CL-CSS-INFOTCNT.1
    card.setTransactionCounter(ByteArrayUtil.extractInt(challengeTransactionCounter, 0, 3, false));
    if (recordData.length > 0) {
      card.setContent((byte) sfi, recordNumber, recordData);
    }
    if (!isCryptoServiceSynchronized()) {
      synchronizeCryptoService(dataOut);
    } else if (!Arrays.equals(dataOut, preOpenDataOut)) {
      throw new CardSecurityContextException(
          "Session has been pre-opened but 'dataOut' fields do not match",
          CardCommandRef.OPEN_SECURE_SESSION);
    }
  }

  /**
   * Returns the KVC to use according to the provided write access and the card's KVC.
   *
   * @return "null" if the card did not provide a KVC value and if there's no default KVC value.
   */
  private Byte computeKvc() {
    if (kvc != null) {
      return kvc;
    }
    return symmetricCryptoSecuritySetting.getDefaultKvc(writeAccessLevel);
  }

  /**
   * Returns the KIF to use according to the provided write access level and KVC.
   *
   * @param kvc The previously computed KVC value.
   * @return "null" if the card did not provide a KIF value and if there's no default KIF value.
   */
  private Byte computeKif(Byte kvc) {
    // CL-KEY-KIF.1
    if ((kif != null && kif != (byte) 0xFF) || (kvc == null)) {
      return kif;
    }
    // CL-KEY-KIFUNK.1
    Byte result = symmetricCryptoSecuritySetting.getKif(writeAccessLevel, kvc);
    if (result == null) {
      result = symmetricCryptoSecuritySetting.getDefaultKif(writeAccessLevel);
    }
    return result;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  void setApduResponseAndCheckStatus(ApduResponseApi apduResponse) throws CardCommandException {
    super.setApduResponseAndCheckStatus(apduResponse);
    byte[] dataOut = apduResponse.getDataOut();
    CalypsoCardAdapter card = getCalypsoCard();
    switch (card.getProductType()) {
      case PRIME_REVISION_1:
        parseRev10(dataOut);
        break;
      case PRIME_REVISION_2:
        parseRev24(dataOut);
        break;
      default:
        parseRev3(dataOut);
    }
    // CL-CSS-INFORAT.1
    card.setDfRatified(isPreviousSessionRatified);
    // CL-CSS-INFOTCNT.1
    card.setTransactionCounter(ByteArrayUtil.extractInt(challengeTransactionCounter, 0, 3, false));
    if (recordData.length > 0) {
      card.setContent((byte) sfi, recordNumber, recordData);
    }
    // If it is a pre-open variant, then we save the pre-open data into the Calypso card image.
    if (apduResponse.getStatusWord() == 0x6200) {
      card.setPreOpenWriteAccessLevel(writeAccessLevel);
      card.setPreOpenDataOut(dataOut);
    }
  }

  /**
   * Parse Rev 3
   *
   * @param apduResponseData The response data.
   */
  private void parseRev3(byte[] apduResponseData) {
    CalypsoCardAdapter card =
        getTransactionContext() != null ? getTransactionContext().getCard() : getCalypsoCard();
    int offset;
    // CL-CSS-OSSRFU.1
    if (isExtendedModeAllowed) {
      offset = 4;
      isPreviousSessionRatified = (apduResponseData[8] & 0x01) == (byte) 0x00;
      boolean manageSecureSessionAuthorized = (apduResponseData[8] & 0x02) == (byte) 0x02;
      if (!manageSecureSessionAuthorized) {
        card.disableExtendedMode();
      }
    } else {
      offset = 0;
      isPreviousSessionRatified = (apduResponseData[4] == (byte) 0x00);
      card.disableExtendedMode();
    }
    challengeTransactionCounter = Arrays.copyOfRange(apduResponseData, 0, 3);
    challengeRandomNumber = Arrays.copyOfRange(apduResponseData, 3, 4 + offset);
    kif = apduResponseData[5 + offset];
    kvc = apduResponseData[6 + offset];
    int dataLength = apduResponseData[7 + offset];
    recordData = Arrays.copyOfRange(apduResponseData, 8 + offset, 8 + offset + dataLength);
  }

  /**
   * Parse Rev 2.4
   *
   * <p>In rev 2.4 mode, the response to the Open Secure Session command is as follows:
   *
   * <p><code>KK CC CC CC CC [RR RR] [NN..NN]</code>
   *
   * <p>Where:
   *
   * <ul>
   *   <li><code>KK</code> = KVC byte CC
   *   <li><code>CC CC CC CC</code> = card challenge
   *   <li><code>RR RR</code> = ratification bytes (may be absent)
   *   <li><code>NN..NN</code> = record data (29 bytes)
   * </ul>
   *
   * Legal length values are:
   *
   * <ul>
   *   <li>5: ratified, 1-byte KCV, 4-byte challenge, no data
   *   <li>34: ratified, 1-byte KCV, 4-byte challenge, 29 bytes of data
   *   <li>7: not ratified (2 ratification bytes), 1-byte KCV, 4-byte challenge, no data
   *   <li>35 not ratified (2 ratification bytes), 1-byte KCV, 4-byte challenge, 29 bytes of data
   * </ul>
   *
   * @param apduResponseData The response data.
   */
  private void parseRev24(byte[] apduResponseData) {
    switch (apduResponseData.length) {
      case 5:
        isPreviousSessionRatified = true;
        recordData = new byte[0];
        break;
      case 34:
        isPreviousSessionRatified = true;
        recordData = Arrays.copyOfRange(apduResponseData, 5, 34);
        break;
      case 7:
        isPreviousSessionRatified = false;
        recordData = new byte[0];
        break;
      case 36:
        isPreviousSessionRatified = false;
        recordData = Arrays.copyOfRange(apduResponseData, 7, 36);
        break;
      default:
        throw new IllegalStateException(
            "Bad response length to Open Secure Session: " + apduResponseData.length);
    }
    challengeTransactionCounter = Arrays.copyOfRange(apduResponseData, 1, 4);
    challengeRandomNumber = Arrays.copyOfRange(apduResponseData, 4, 5);
    kif = null;
    kvc = apduResponseData[0];
  }

  /**
   * Parse Rev 1.0
   *
   * <p>In rev 1.0 mode, the response to the Open Secure Session command is as follows:
   *
   * <p><code>CC CC CC CC [RR RR] [NN..NN]</code>
   *
   * <p>Where:
   *
   * <ul>
   *   <li><code>CC CC CC CC</code> = card challenge
   *   <li><code>RR RR</code> = ratification bytes (may be absent)
   *   <li><code>NN..NN</code> = record data (29 bytes)
   * </ul>
   *
   * Legal length values are:
   *
   * <ul>
   *   <li>4: ratified, 4-byte challenge, no data
   *   <li>33: ratified, 4-byte challenge, 29 bytes of data
   *   <li>6: not ratified (2 ratification bytes), 4-byte challenge, no data
   *   <li>35 not ratified (2 ratification bytes), 4-byte challenge, 29 bytes of data
   * </ul>
   *
   * @param apduResponseData The response data.
   */
  private void parseRev10(byte[] apduResponseData) {
    switch (apduResponseData.length) {
      case 4:
        isPreviousSessionRatified = true;
        recordData = new byte[0];
        break;
      case 33:
        isPreviousSessionRatified = true;
        recordData = Arrays.copyOfRange(apduResponseData, 4, 33);
        break;
      case 6:
        isPreviousSessionRatified = false;
        recordData = new byte[0];
        break;
      case 35:
        isPreviousSessionRatified = false;
        recordData = Arrays.copyOfRange(apduResponseData, 6, 35);
        break;
      default:
        throw new IllegalStateException(
            "Bad response length to Open Secure Session: " + apduResponseData.length);
    }
    challengeTransactionCounter = Arrays.copyOfRange(apduResponseData, 0, 3);
    challengeRandomNumber = Arrays.copyOfRange(apduResponseData, 3, 4);
    kif = null;
    kvc = null;
  }

  /**
   * @return A non empty value.
   * @since 2.0.1
   */
  byte[] getCardChallenge() {
    return challengeRandomNumber;
  }

  /**
   * @return The current KIF.
   * @since 2.0.1
   */
  Byte getKif() {
    return kif;
  }

  /**
   * @return The current KVC.
   * @since 2.0.1
   */
  Byte getKvc() {
    return kvc;
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
