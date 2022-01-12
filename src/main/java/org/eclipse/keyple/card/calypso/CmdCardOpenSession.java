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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the Open Secure Session APDU command.
 *
 * @since 2.0.1
 */
final class CmdCardOpenSession extends AbstractCardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardOpenSession.class);
  private static final String EXTRA_INFO_FORMAT = "KEYINDEX:%d, SFI:%02Xh, REC:%d";

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
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
            "P1 or P2 value not supported (key index incorrect, wrong P2).",
            CardIllegalParameterException.class));
    m.put(0x61FF, new StatusProperties("Correct execution (ISO7816 T=0).", null));
    STATUS_TABLE = m;
  }

  private final CalypsoCard calypsoCard;

  private int sfi;
  private int recordNumber;

  /** The secure session. */
  private SecureSession secureSession;

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardOpenSession.
   *
   * @param calypsoCard the {@link CalypsoCard}.
   * @throws IllegalArgumentException If the key index is 0 and rev is 2.4
   * @throws IllegalArgumentException If the request is inconsistent
   * @since 2.0.1
   */
  CmdCardOpenSession(
      CalypsoCard calypsoCard,
      byte debitKeyIndex,
      byte[] sessionTerminalChallenge,
      int sfi,
      int recordNumber) {

    super(CalypsoCardCommand.OPEN_SESSION);

    this.calypsoCard = calypsoCard;
    switch (calypsoCard.getProductType()) {
      case PRIME_REVISION_1:
        createRev10(debitKeyIndex, sessionTerminalChallenge, sfi, recordNumber);
        break;
      case PRIME_REVISION_2:
        createRev24(debitKeyIndex, sessionTerminalChallenge, sfi, recordNumber);
        break;
      case PRIME_REVISION_3:
      case LIGHT:
      case BASIC:
        createRev3(debitKeyIndex, sessionTerminalChallenge, sfi, recordNumber, calypsoCard);
        break;
      default:
        throw new IllegalArgumentException(
            "Product type " + calypsoCard.getProductType() + " isn't supported");
    }
  }

  /**
   * (private)<br>
   * Create Rev 3
   *
   * @param keyIndex the key index.
   * @param samChallenge the sam challenge returned by the SAM Get Challenge APDU command.
   * @param sfi the sfi to select.
   * @param recordNumber the record number to read.
   * @param calypsoCard The {@link CalypsoCard}.
   * @throws IllegalArgumentException If the request is inconsistent
   */
  private void createRev3(
      byte keyIndex, byte[] samChallenge, int sfi, int recordNumber, CalypsoCard calypsoCard) {

    this.sfi = sfi;
    this.recordNumber = recordNumber;

    byte p1 = (byte) ((recordNumber * 8) + keyIndex);
    byte p2;
    byte[] dataIn;

    // CL-CSS-OSSMODE.1 fullfilled only for SAM C1
    if (!calypsoCard.isExtendedModeSupported()) {
      p2 = (byte) ((sfi * 8) + 1);
      dataIn = samChallenge;
    } else {
      p2 = (byte) ((sfi * 8) + 2);
      dataIn = new byte[samChallenge.length + 1];
      dataIn[0] = (byte) 0x00;
      System.arraycopy(samChallenge, 0, dataIn, 1, samChallenge.length);
    }

    /*
     * case 4: this command contains incoming and outgoing data. We define le = 0, the actual
     * length will be processed by the lower layers.
     */
    byte le = 0;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                CalypsoCardClass.ISO.getValue(),
                CalypsoCardCommand.OPEN_SESSION.getInstructionByte(),
                p1,
                p2,
                dataIn,
                le)));

    if (logger.isDebugEnabled()) {
      String extraInfo = String.format(EXTRA_INFO_FORMAT, keyIndex, sfi, recordNumber);
      addSubName(extraInfo);
    }
  }

  /**
   * (private)<br>
   * Create Rev 2.4
   *
   * @param keyIndex the key index.
   * @param samChallenge the sam challenge returned by the SAM Get Challenge APDU command.
   * @param sfi the sfi to select.
   * @param recordNumber the record number to read.
   * @throws IllegalArgumentException If key index is 0 (rev 2.4)
   * @throws IllegalArgumentException If the request is inconsistent
   */
  private void createRev24(byte keyIndex, byte[] samChallenge, int sfi, int recordNumber) {

    if (keyIndex == 0x00) {
      throw new IllegalArgumentException("Key index can't be zero for rev 2.4!");
    }

    this.sfi = sfi;
    this.recordNumber = recordNumber;

    byte p1 = (byte) (0x80 + (recordNumber * 8) + keyIndex);

    buildLegacyApduRequest(keyIndex, samChallenge, sfi, recordNumber, p1);
  }

  /**
   * (private)<br>
   * Create Rev 1.0
   *
   * @param keyIndex the key index.
   * @param samChallenge the sam challenge returned by the SAM Get Challenge APDU command.
   * @param sfi the sfi to select.
   * @param recordNumber the record number to read.
   * @throws IllegalArgumentException If key index is 0 (rev 1.0)
   * @throws IllegalArgumentException If the request is inconsistent
   */
  private void createRev10(byte keyIndex, byte[] samChallenge, int sfi, int recordNumber) {

    if (keyIndex == 0x00) {
      throw new IllegalArgumentException("Key index can't be zero for rev 1.0!");
    }

    this.sfi = sfi;
    this.recordNumber = recordNumber;

    byte p1 = (byte) ((recordNumber * 8) + keyIndex);

    buildLegacyApduRequest(keyIndex, samChallenge, sfi, recordNumber, p1);
  }

  /**
   * (private)<br>
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
    byte le = 0;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                CalypsoCardClass.LEGACY.getValue(),
                CalypsoCardCommand.OPEN_SESSION.getInstructionByte(),
                p1,
                p2,
                samChallenge,
                le)));

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
   * (package-private)<br>
   *
   * @return the SFI of the file read while opening the secure session
   * @since 2.0.1
   */
  int getSfi() {
    return sfi;
  }

  /**
   * (package-private)<br>
   *
   * @return the record number to read
   * @since 2.0.1
   */
  int getRecordNumber() {
    return recordNumber;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  CmdCardOpenSession setApduResponse(ApduResponseApi apduResponse) {
    super.setApduResponse(apduResponse);
    byte[] dataOut = getApduResponse().getDataOut();
    if (dataOut.length > 0) {
      switch (calypsoCard.getProductType()) {
        case PRIME_REVISION_1:
          parseRev10(dataOut);
          break;
        case PRIME_REVISION_2:
          parseRev24(dataOut);
          break;
        default:
          parseRev3(dataOut);
      }
    }
    return this;
  }

  /**
   * (private)<br>
   * Parse Rev 3
   *
   * @param apduResponseData The response data.
   */
  private void parseRev3(byte[] apduResponseData) {

    boolean previousSessionRatified;
    boolean manageSecureSessionAuthorized;
    int offset;

    // CL-CSS-OSSRFU.1
    if (!calypsoCard.isExtendedModeSupported()) {
      offset = 0;
      previousSessionRatified = (apduResponseData[4] == (byte) 0x00);
      manageSecureSessionAuthorized = false;
    } else {
      offset = 4;
      previousSessionRatified = (apduResponseData[8] & 0x01) == (byte) 0x00;
      manageSecureSessionAuthorized = (apduResponseData[8] & 0x02) == (byte) 0x02;
    }

    byte kif = apduResponseData[5 + offset];
    byte kvc = apduResponseData[6 + offset];
    int dataLength = apduResponseData[7 + offset];
    byte[] data = Arrays.copyOfRange(apduResponseData, 8 + offset, 8 + offset + dataLength);

    this.secureSession =
        new SecureSession(
            Arrays.copyOfRange(apduResponseData, 0, 3),
            Arrays.copyOfRange(apduResponseData, 3, 4 + offset),
            previousSessionRatified,
            manageSecureSessionAuthorized,
            kif,
            kvc,
            data,
            apduResponseData);
  }

  /**
   * (private)<br>
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

    boolean previousSessionRatified;

    byte[] data;

    switch (apduResponseData.length) {
      case 5:
        previousSessionRatified = true;
        data = new byte[0];
        break;
      case 34:
        previousSessionRatified = true;
        data = Arrays.copyOfRange(apduResponseData, 5, 34);
        break;
      case 7:
        previousSessionRatified = false;
        data = new byte[0];
        break;
      case 36:
        previousSessionRatified = false;
        data = Arrays.copyOfRange(apduResponseData, 7, 36);
        break;
      default:
        throw new IllegalStateException(
            "Bad response length to Open Secure Session: " + apduResponseData.length);
    }

    byte kvc = apduResponseData[0];

    this.secureSession =
        new SecureSession(
            Arrays.copyOfRange(apduResponseData, 1, 4),
            Arrays.copyOfRange(apduResponseData, 4, 5),
            previousSessionRatified,
            false,
            null,
            kvc,
            data,
            apduResponseData);
  }

  /**
   * (private)<br>
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

    boolean previousSessionRatified;

    byte[] data;

    switch (apduResponseData.length) {
      case 4:
        previousSessionRatified = true;
        data = new byte[0];
        break;
      case 33:
        previousSessionRatified = true;
        data = Arrays.copyOfRange(apduResponseData, 4, 33);
        break;
      case 6:
        previousSessionRatified = false;
        data = new byte[0];
        break;
      case 35:
        previousSessionRatified = false;
        data = Arrays.copyOfRange(apduResponseData, 6, 35);
        break;
      default:
        throw new IllegalStateException(
            "Bad response length to Open Secure Session: " + apduResponseData.length);
    }

    /* KVC doesn't exist and is set to null for this type of card */
    this.secureSession =
        new SecureSession(
            Arrays.copyOfRange(apduResponseData, 0, 3),
            Arrays.copyOfRange(apduResponseData, 3, 4),
            previousSessionRatified,
            false,
            null,
            null,
            data,
            apduResponseData);
  }

  /**
   * (package-private)<br>
   *
   * @return A non empty value.
   * @since 2.0.1
   */
  byte[] getCardChallenge() {
    return secureSession.getChallengeRandomNumber();
  }

  /**
   * (package-private)<br>
   *
   * @return A non negative number.
   * @since 2.0.1
   */
  int getTransactionCounterValue() {
    return ByteArrayUtil.threeBytesToInt(secureSession.getChallengeTransactionCounter(), 0);
  }

  /**
   * (package-private)<br>
   *
   * @return True if the previous session was ratified.
   * @since 2.0.1
   */
  boolean wasRatified() {
    return secureSession.isPreviousSessionRatified();
  }

  /**
   * (package-private)<br>
   *
   * @return True if the managed secure session is authorized.
   * @since 2.0.1
   */
  boolean isManageSecureSessionAuthorized() {
    return secureSession.isManageSecureSessionAuthorized();
  }

  /**
   * (package-private)<br>
   *
   * @return The current KIF.
   * @since 2.0.1
   */
  Byte getSelectedKif() {
    return secureSession.getKIF();
  }

  /**
   * (package-private)<br>
   *
   * @return The current KVC.
   * @since 2.0.1
   */
  Byte getSelectedKvc() {
    return secureSession.getKVC();
  }

  /**
   * (package-private)<br>
   *
   * @return The optional read data.
   * @since 2.0.1
   */
  byte[] getRecordDataRead() {
    return secureSession.getOriginalData();
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

  /**
   * (private)<br>
   * The Class SecureSession.
   */
  private static class SecureSession {

    /** Challenge transaction counter */
    private final byte[] challengeTransactionCounter;

    /** Challenge random number */
    private final byte[] challengeRandomNumber;

    /** The previous session ratified boolean. */
    private final boolean previousSessionRatified;

    /** The manage secure session authorized boolean. */
    private final boolean manageSecureSessionAuthorized;

    /** The kif (it may be null if it doesn't exist in the considered card [rev 1.0]). */
    private final Byte kif;

    /** The kvc (it may be null if it doesn't exist in the considered card [rev 1.0]). */
    private final Byte kvc;

    /** The original data. */
    private final byte[] originalData;

    /** The secure session data. */
    private final byte[] secureSessionData;

    /**
     * Instantiates a new SecureSession
     *
     * @param challengeTransactionCounter Challenge transaction counter.
     * @param challengeRandomNumber Challenge random number.
     * @param previousSessionRatified the previous session ratified.
     * @param manageSecureSessionAuthorized the manage secure session authorized.
     * @param kif the KIF from the response of the open secure session APDU command.
     * @param kvc the KVC from the response of the open secure session APDU command.
     * @param originalData the original data from the response of the open secure session APDU.
     *     command
     * @param secureSessionData the secure session data from the response of open secure session.
     *     APDU command
     * @since 2.0.1
     */
    private SecureSession( // NOSONAR
        byte[] challengeTransactionCounter,
        byte[] challengeRandomNumber,
        boolean previousSessionRatified,
        boolean manageSecureSessionAuthorized,
        Byte kif,
        Byte kvc,
        byte[] originalData,
        byte[] secureSessionData) {
      this.challengeTransactionCounter = challengeTransactionCounter;
      this.challengeRandomNumber = challengeRandomNumber;
      this.previousSessionRatified = previousSessionRatified;
      this.manageSecureSessionAuthorized = manageSecureSessionAuthorized;
      this.kif = kif;
      this.kvc = kvc;
      this.originalData = originalData;
      this.secureSessionData = secureSessionData;
    }

    public byte[] getChallengeTransactionCounter() {
      return challengeTransactionCounter;
    }

    public byte[] getChallengeRandomNumber() {
      return challengeRandomNumber;
    }

    /**
     * Checks if is previous session ratified.
     *
     * @return The boolean
     * @since 2.0.1
     */
    public boolean isPreviousSessionRatified() {
      return previousSessionRatified;
    }

    /**
     * Checks if is manage secure session authorized.
     *
     * @return True if the secure session is authorized
     * @since 2.0.1
     */
    public boolean isManageSecureSessionAuthorized() {
      return manageSecureSessionAuthorized;
    }

    /**
     * Gets the kif.
     *
     * @return A byte
     * @since 2.0.1
     */
    public Byte getKIF() {
      return kif;
    }

    /**
     * Gets the kvc.
     *
     * @return A byte
     * @since 2.0.1
     */
    public Byte getKVC() {
      return kvc;
    }

    /**
     * Gets the original data.
     *
     * @return An array of bytes
     * @since 2.0.1
     */
    public byte[] getOriginalData() {
      return originalData;
    }

    /**
     * Gets the secure session data.
     *
     * @return An array of bytes
     * @since 2.0.1
     */
    public byte[] getSecureSessionData() {
      return secureSessionData;
    }
  }
}
