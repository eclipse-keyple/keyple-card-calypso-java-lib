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

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.card.calypso.card.CardRevision;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * (package-private)<br>
 * Parses the Open session response.
 *
 * @since 2.0
 */
abstract class AbstractCardOpenSessionParser extends AbstractCardResponseParser {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties(
            "Lc value not supported.", CalypsoCardIllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties("Transaction Counter is 0", CalypsoCardTerminatedException.class));
    m.put(
        0x6981,
        new StatusProperties(
            "Command forbidden (read requested and current EF is a Binary file).",
            CalypsoCardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (PIN code not presented, AES key forbidding the "
                + "compatibility mode, encryption required).",
            CalypsoCardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, Session already opened).",
            CalypsoCardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Command not allowed (read requested and no current EF).",
            CalypsoCardDataAccessException.class));
    m.put(
        0x6A81,
        new StatusProperties("Wrong key index.", CalypsoCardIllegalParameterException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CalypsoCardDataAccessException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found (record index is above NumRec).",
            CalypsoCardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties(
            "P1 or P2 value not supported (key index incorrect, wrong P2).",
            CalypsoCardIllegalParameterException.class));
    m.put(0x61FF, new StatusProperties("Correct execution (ISO7816 T=0).", null));
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

  /** The secure session. */
  SecureSession secureSession;

  /**
   * Instantiates a new AbstractCardOpenSessionParser.
   *
   * @param response the response from Open secure session APDU command.
   * @param builder the reference to the builder that created this parser.
   * @param revision the revision of the card.
   * @since 2.0
   */
  AbstractCardOpenSessionParser(
      ApduResponseApi response,
      AbstractCardOpenSessionBuilder<AbstractCardOpenSessionParser> builder,
      CardRevision revision) {
    super(response, builder);
    byte[] dataOut = response.getDataOut();
    if (dataOut.length > 0) {
      this.secureSession = toSecureSession(dataOut);
    }
  }

  public AbstractCardOpenSessionParser create(ApduResponseApi response, CardRevision revision) {
    switch (revision) {
      case REV1_0:
        return new CardOpenSession10Parser(response, (CardOpenSession10Builder) builder);
      case REV2_4:
        return new CardOpenSession24Parser(response, (CardOpenSession24Builder) builder);
      case REV3_1:
      case REV3_1_CLAP:
        return new CardOpenSession31Parser(response, (CardOpenSession31Builder) builder);
      case REV3_2:
        return new CardOpenSession32Parser(response, (CardOpenSession32Builder) builder);
      default:
        throw new IllegalArgumentException("Unknow revision " + revision);
    }
  }

  abstract SecureSession toSecureSession(byte[] apduResponseData);

  public byte[] getCardChallenge() {
    return secureSession.getChallengeRandomNumber();
  }

  public int getTransactionCounterValue() {
    return ByteArrayUtil.threeBytesToInt(secureSession.getChallengeTransactionCounter(), 0);
  }

  public boolean wasRatified() {
    return secureSession.isPreviousSessionRatified();
  }

  public boolean isManageSecureSessionAuthorized() {
    return secureSession.isManageSecureSessionAuthorized();
  }

  public byte getSelectedKif() {
    return secureSession.getKIF();
  }

  public byte getSelectedKvc() {
    return secureSession.getKVC();
  }

  public byte[] getRecordDataRead() {
    return secureSession.getOriginalData();
  }

  /** The Class SecureSession. A secure session is returned by a open secure session command */
  public static class SecureSession {

    /** Challenge transaction counter */
    private final byte[] challengeTransactionCounter;

    /** Challenge random number */
    private final byte[] challengeRandomNumber;

    /** The previous session ratified boolean. */
    private final boolean previousSessionRatified;

    /** The manage secure session authorized boolean. */
    private final boolean manageSecureSessionAuthorized;

    /** The kif. */
    private final byte kif;

    /** The kvc (may be null if it doesn't exist in the considered card [rev 1.0]). */
    private final Byte kvc;

    /** The original data. */
    private final byte[] originalData;

    /** The secure session data. */
    private final byte[] secureSessionData;

    /**
     * Instantiates a new SecureSession for a Calypso application revision 3
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
     * @since 2.0
     */
    public SecureSession(
        byte[] challengeTransactionCounter,
        byte[] challengeRandomNumber,
        boolean previousSessionRatified,
        boolean manageSecureSessionAuthorized,
        byte kif,
        byte kvc,
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

    /**
     * Instantiates a new SecureSession for a Calypso application revision 2.4
     *
     * @param challengeTransactionCounter Challenge transaction counter.
     * @param challengeRandomNumber Challenge random number.
     * @param previousSessionRatified the previous session ratified.
     * @param manageSecureSessionAuthorized the manage secure session authorized.
     * @param kvc the KVC from the response of the open secure session APDU command.
     * @param originalData the original data from the response of the open secure session APDU.
     *     command
     * @param secureSessionData the secure session data from the response of open secure session.
     *     APDU command
     * @since 2.0
     */
    public SecureSession(
        byte[] challengeTransactionCounter,
        byte[] challengeRandomNumber,
        boolean previousSessionRatified,
        boolean manageSecureSessionAuthorized,
        Byte kvc,
        byte[] originalData,
        byte[] secureSessionData) {
      this.challengeTransactionCounter = challengeTransactionCounter;
      this.challengeRandomNumber = challengeRandomNumber;
      this.previousSessionRatified = previousSessionRatified;
      this.manageSecureSessionAuthorized = manageSecureSessionAuthorized;
      this.kif = (byte) 0xFF;
      this.kvc = kvc != null ? kvc : (byte) 0xFF;
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
     * @since 2.0
     */
    public boolean isPreviousSessionRatified() {
      return previousSessionRatified;
    }

    /**
     * Checks if is manage secure session authorized.
     *
     * @return True if the secure session is authorized
     * @since 2.0
     */
    public boolean isManageSecureSessionAuthorized() {
      return manageSecureSessionAuthorized;
    }

    /**
     * Gets the kif.
     *
     * @return A byte
     * @since 2.0
     */
    public byte getKIF() {
      return kif;
    }

    /**
     * Gets the kvc.
     *
     * @return A byte
     * @since 2.0
     */
    public byte getKVC() {
      return kvc;
    }

    /**
     * Gets the original data.
     *
     * @return An array of bytes
     * @since 2.0
     */
    public byte[] getOriginalData() {
      return originalData;
    }

    /**
     * Gets the secure session data.
     *
     * @return An array of bytes
     * @since 2.0
     */
    public byte[] getSecureSessionData() {
      return secureSessionData;
    }
  }
}
