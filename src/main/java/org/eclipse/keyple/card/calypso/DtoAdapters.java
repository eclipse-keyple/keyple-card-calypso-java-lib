/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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

import java.util.*;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.calypso.card.card.SvDebitLogRecord;
import org.eclipse.keypop.calypso.card.card.SvLoadLogRecord;
import org.eclipse.keypop.calypso.card.transaction.SearchCommandData;
import org.eclipse.keypop.calypso.crypto.asymmetric.transaction.spi.AsymmetricCryptoCardTransactionManagerSpi;
import org.eclipse.keypop.calypso.crypto.symmetric.SvCommandSecurityDataApi;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoCardTransactionManagerSpi;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardRequestSpi;
import org.eclipse.keypop.card.spi.CardSelectionRequestSpi;

final class DtoAdapters {

  private DtoAdapters() {}

  /**
   * This POJO contains a set of data related to an ISO-7816 APDU command.
   *
   * <ul>
   *   <li>A byte array containing the raw APDU data.
   *   <li>A flag indicating if the APDU is of type 4 (ingoing and outgoing data).
   *   <li>An optional set of integers corresponding to valid status words in response to this APDU.
   * </ul>
   *
   * Attaching an optional name to the request facilitates the enhancement of the application logs
   * using the toString method.
   *
   * @since 2.0.0
   */
  static final class ApduRequestAdapter implements ApduRequestSpi {

    private static final int DEFAULT_SUCCESSFUL_CODE = 0x9000;

    private byte[] apdu;
    private final Set<Integer> successfulStatusWords;
    private String info;

    /**
     * Builds an APDU request from a raw byte buffer.
     *
     * <p>The default status words list is initialized with the standard successful code 9000h.
     *
     * @param apdu The bytes of the APDU's body.
     * @since 2.0.0
     */
    ApduRequestAdapter(byte[] apdu) {
      this.apdu = apdu;
      successfulStatusWords = new HashSet<Integer>();
      successfulStatusWords.add(DEFAULT_SUCCESSFUL_CODE);
    }

    /**
     * Adds a status word to the list of those that should be considered successful for the APDU.
     *
     * <p>Note: initially, the list contains the standard successful status word {@code 9000h}.
     *
     * @param successfulStatusWord A positive int &le; {@code FFFFh}.
     * @return The object instance.
     * @since 2.0.0
     */
    ApduRequestAdapter addSuccessfulStatusWord(int successfulStatusWord) {
      successfulStatusWords.add(successfulStatusWord);
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public Set<Integer> getSuccessfulStatusWords() {
      return successfulStatusWords;
    }

    /**
     * Names the APDU request.
     *
     * <p>This string is dedicated to improve the readability of logs and should therefore only be
     * invoked conditionally (e.g. when log level &gt;= debug).
     *
     * @param info The request name (free text).
     * @return The object instance.
     * @since 2.0.0
     */
    ApduRequestAdapter setInfo(String info) {
      this.info = info;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public String getInfo() {
      return info;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte[] getApdu() {
      return apdu;
    }

    /**
     * Sets the APDU.
     *
     * @param apdu The APDU to set.
     * @since 2.3.2
     */
    void setApdu(byte[] apdu) {
      this.apdu = apdu;
    }

    /**
     * Converts the APDU request into a string where the data is encoded in a json format.
     *
     * @return A not empty String
     * @since 2.0.0
     */
    @Override
    public String toString() {
      return "APDU_REQUEST = " + JsonUtil.toJson(this);
    }
  }

  /**
   * This POJO contains an ordered list of {@link ApduRequestSpi} and the associated status code
   * check policy.
   *
   * @since 2.0.0
   */
  static final class CardRequestAdapter implements CardRequestSpi {

    private final List<ApduRequestSpi> apduRequests;
    private final boolean isStatusCodesVerificationEnabled;

    /**
     * Builds a card request with a list of {@link ApduRequestSpi } and the flag indicating the
     * expected response checking behavior.
     *
     * <p>When the status code verification is enabled, the transmission of the APDUs must be
     * interrupted as soon as the status code of a response is unexpected.
     *
     * @param apduRequests A not empty list.
     * @param isStatusCodesVerificationEnabled true or false.
     * @since 2.0.0
     */
    CardRequestAdapter(
        List<ApduRequestSpi> apduRequests, boolean isStatusCodesVerificationEnabled) {
      this.apduRequests = apduRequests;
      this.isStatusCodesVerificationEnabled = isStatusCodesVerificationEnabled;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public List<ApduRequestSpi> getApduRequests() {
      return apduRequests;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public boolean stopOnUnsuccessfulStatusWord() {
      return isStatusCodesVerificationEnabled;
    }

    /**
     * Converts the card request into a string where the data is encoded in a json format.
     *
     * @return A not empty String
     * @since 2.0.0
     */
    @Override
    public String toString() {
      return "CARD_REQUEST = " + JsonUtil.toJson(this);
    }
  }

  /**
   * This POJO contains the APDU to be executed in a selection case.
   *
   * <p>A selection case is defined by a {@link org.eclipse.keypop.reader.selection.CardSelector}
   * that target a particular smart card and an optional {@link CardRequestSpi} containing
   * additional APDU commands to be sent to the card when the selection is successful.
   *
   * @since 2.0.0
   */
  static final class CardSelectionRequestAdapter implements CardSelectionRequestSpi {

    private static final int SW_DEFAULT_SUCCESSFUL = 0x9000;
    private final CardRequestSpi cardRequest;
    private final Set<Integer> successfulSelectionStatusWords;

    /**
     * Builds additional APDUs to be sent after the selection step.
     *
     * @param cardRequest The card request.
     * @since 2.0.0
     */
    CardSelectionRequestAdapter(CardRequestSpi cardRequest) {
      this.cardRequest = cardRequest;
      successfulSelectionStatusWords = new LinkedHashSet<Integer>(2);
      successfulSelectionStatusWords.add(SW_DEFAULT_SUCCESSFUL);
    }

    /**
     * Adds the status word to the acceptation list.
     *
     * @param successfulStatusWord The status word to add.
     * @since 3.0.0
     */
    void addSuccessfulSelectionStatusWord(int successfulStatusWord) {
      successfulSelectionStatusWords.add(successfulStatusWord);
    }

    @Override
    public Set<Integer> getSuccessfulSelectionStatusWords() {
      return successfulSelectionStatusWords;
    }

    /**
     * Gets the card request.
     *
     * @return a {@link CardRequestSpi} or null if it has not been defined
     * @since 2.0.0
     */
    @Override
    public CardRequestSpi getCardRequest() {
      return cardRequest;
    }

    /**
     * Converts the card selection request into a string where the data is encoded in a json format.
     *
     * @return A not empty String
     * @since 2.0.0
     */
    @Override
    public String toString() {
      return "CARD_SELECTION_REQUEST = " + JsonUtil.toJson(this);
    }
  }

  /**
   * Implementation of {@link SearchCommandData}.
   *
   * @since 2.1.0
   */
  static final class SearchCommandDataAdapter implements SearchCommandData {

    private byte sfi = 1;
    private int recordNumber = 1;
    private int offset;
    private boolean enableRepeatedOffset;
    private byte[] searchData;
    private byte[] mask;
    private boolean fetchFirstMatchingResult;
    private final List<Integer> matchingRecordNumbers = new ArrayList<Integer>(1);

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    @Override
    public SearchCommandData setSfi(byte sfi) {
      this.sfi = sfi;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    @Override
    public SearchCommandData startAtRecord(int recordNumber) {
      this.recordNumber = recordNumber;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    @Override
    public SearchCommandData setOffset(int offset) {
      this.offset = offset;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    @Override
    public SearchCommandData enableRepeatedOffset() {
      enableRepeatedOffset = true;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    @Override
    public SearchCommandData setSearchData(byte[] data) {
      searchData = data;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    @Override
    public SearchCommandData setMask(byte[] mask) {
      this.mask = mask;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    @Override
    public SearchCommandData fetchFirstMatchingResult() {
      fetchFirstMatchingResult = true;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    @Override
    public List<Integer> getMatchingRecordNumbers() {
      return matchingRecordNumbers;
    }

    /**
     * @return The provided SFI or 0 if it is not set.
     * @since 2.1.0
     */
    byte getSfi() {
      return sfi;
    }

    /**
     * @return The provided record number or 1 if it is not set.
     * @since 2.1.0
     */
    int getRecordNumber() {
      return recordNumber;
    }

    /**
     * @return The provided offset or 0 if it is not set.
     * @since 2.1.0
     */
    int getOffset() {
      return offset;
    }

    /**
     * @return True if repeated offset is enabled.
     * @since 2.1.0
     */
    boolean isEnableRepeatedOffset() {
      return enableRepeatedOffset;
    }

    /**
     * @return A not empty array of search data. It is required to check input data first.
     * @since 2.1.0
     */
    byte[] getSearchData() {
      return searchData;
    }

    /**
     * @return Null if the mask is not set.
     * @since 2.1.0
     */
    byte[] getMask() {
      return mask;
    }

    /**
     * @return True if first matching result needs to be fetched.
     * @since 2.1.0
     */
    boolean isFetchFirstMatchingResult() {
      return fetchFirstMatchingResult;
    }
  }

  /**
   * Adapter of {@link SvCommandSecurityDataApi}
   *
   * @since 2.3.1
   */
  static final class SvCommandSecurityDataApiAdapter implements SvCommandSecurityDataApi {

    private byte[] svGetRequest;
    private byte[] svGetResponse;
    private byte[] svCommandPartialRequest;
    private byte[] serialNumber;
    private byte[] transactionNumber;
    private byte[] terminalChallenge;
    private byte[] terminalSvMac;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    @Override
    public byte[] getSvGetRequest() {
      return svGetRequest;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    @Override
    public byte[] getSvGetResponse() {
      return svGetResponse;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    @Override
    public byte[] getSvCommandPartialRequest() {
      return svCommandPartialRequest;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    @Override
    public SvCommandSecurityDataApiAdapter setSerialNumber(byte[] serialNumber) {
      this.serialNumber = serialNumber;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    @Override
    public SvCommandSecurityDataApiAdapter setTransactionNumber(byte[] transactionNumber) {
      this.transactionNumber = transactionNumber;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    @Override
    public SvCommandSecurityDataApiAdapter setTerminalChallenge(byte[] terminalChallenge) {
      this.terminalChallenge = terminalChallenge;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    @Override
    public SvCommandSecurityDataApiAdapter setTerminalSvMac(byte[] terminalSvMac) {
      this.terminalSvMac = terminalSvMac;
      return this;
    }

    SvCommandSecurityDataApi setSvGetRequest(byte[] svGetRequest) {
      this.svGetRequest = svGetRequest;
      return this;
    }

    SvCommandSecurityDataApi setSvGetResponse(byte[] svGetResponse) {
      this.svGetResponse = svGetResponse;
      return this;
    }

    SvCommandSecurityDataApi setSvCommandPartialRequest(byte[] svCommandPartialRequest) {
      this.svCommandPartialRequest = svCommandPartialRequest;
      return this;
    }

    byte[] getSerialNumber() {
      return serialNumber;
    }

    byte[] getTransactionNumber() {
      return transactionNumber;
    }

    byte[] getTerminalChallenge() {
      return terminalChallenge;
    }

    byte[] getTerminalSvMac() {
      return terminalSvMac;
    }
  }

  /**
   * Implementation of {@link SvDebitLogRecord}.
   *
   * @since 2.0.0
   */
  static final class SvDebitLogRecordAdapter implements SvDebitLogRecord {
    private final int offset;
    private final byte[] cardResponse;

    /**
     * Constructor
     *
     * @param cardResponse the Sv Get or Read Record (SV Load log file) response data.
     * @param offset the debit log offset in the response (may change from a card to another).
     */
    SvDebitLogRecordAdapter(byte[] cardResponse, int offset) {
      this.cardResponse = cardResponse;
      this.offset = offset;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte[] getRawData() {
      return cardResponse;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public int getAmount() {
      return ByteArrayUtil.extractInt(cardResponse, offset, 2, true);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public int getBalance() {
      return ByteArrayUtil.extractInt(cardResponse, offset + 14, 3, true);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte[] getDebitTime() {
      byte[] time = new byte[2];
      time[0] = cardResponse[offset + 4];
      time[1] = cardResponse[offset + 5];
      return time;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte[] getDebitDate() {
      byte[] date = new byte[2];
      date[0] = cardResponse[offset + 2];
      date[1] = cardResponse[offset + 3];
      return date;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte getKvc() {
      return cardResponse[offset + 6];
    }
    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte[] getSamId() {
      byte[] samId = new byte[4];
      System.arraycopy(cardResponse, offset + 7, samId, 0, 4);
      return samId;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public int getSvTNum() {
      byte[] tnNum = new byte[2];
      tnNum[0] = cardResponse[offset + 17];
      tnNum[1] = cardResponse[offset + 18];
      return ByteArrayUtil.extractInt(tnNum, 0, 2, false);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public int getSamTNum() {
      byte[] samTNum = new byte[3];
      System.arraycopy(cardResponse, offset + 11, samTNum, 0, 3);
      return ByteArrayUtil.extractInt(samTNum, 0, 3, false);
    }

    /**
     * Gets the object content as a Json string.
     *
     * @return A not empty string.
     * @since 2.0.0
     */
    @Override
    public String toString() {
      return "{\"amount\":"
          + getAmount()
          + ",\"balance\":"
          + getBalance()
          + ",\"debitDate\":\""
          + HexUtil.toHex(getDebitDate())
          + "\",\"debitTime\":\""
          + HexUtil.toHex(getDebitTime())
          + "\",\"kvc\":\""
          + HexUtil.toHex(getKvc())
          + "\",\"samId\":\""
          + HexUtil.toHex(getSamId())
          + "\",\"svTransactionNumber\":"
          + getSvTNum()
          + ",\"svSamTransactionNumber\":"
          + getSamTNum()
          + "}";
    }
  }

  /**
   * Implementation of {@link SvLoadLogRecord}.
   *
   * @since 2.0.0
   */
  static final class SvLoadLogRecordAdapter implements SvLoadLogRecord {
    private final int offset;
    private final byte[] cardResponse;

    /**
     * Constructor
     *
     * @param cardResponse the Sv Get or Read Record (SV Debit log file) response data.
     * @param offset the load log offset in the response (may change from a card to another).
     * @since 2.0.0
     */
    SvLoadLogRecordAdapter(byte[] cardResponse, int offset) {
      this.cardResponse = cardResponse;
      this.offset = offset;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte[] getRawData() {
      return cardResponse;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public int getAmount() {
      return ByteArrayUtil.extractInt(cardResponse, offset + 8, 3, true);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public int getBalance() {
      return ByteArrayUtil.extractInt(cardResponse, offset + 5, 3, true);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte[] getLoadTime() {
      byte[] time = new byte[2];
      time[0] = cardResponse[offset + 11];
      time[1] = cardResponse[offset + 12];
      return time;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte[] getLoadDate() {
      byte[] date = new byte[2];
      date[0] = cardResponse[offset];
      date[1] = cardResponse[offset + 1];
      return date;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte[] getFreeData() {
      byte[] free = new byte[2];
      free[0] = cardResponse[offset + 2];
      free[1] = cardResponse[offset + 4];
      return free;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte getKvc() {
      return cardResponse[offset + 3];
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte[] getSamId() {
      byte[] samId = new byte[4];
      System.arraycopy(cardResponse, offset + 13, samId, 0, 4);
      return samId;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public int getSvTNum() {
      byte[] tnNum = new byte[2];
      tnNum[0] = cardResponse[offset + 20];
      tnNum[1] = cardResponse[offset + 21];
      return ByteArrayUtil.extractInt(tnNum, 0, 2, false);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public int getSamTNum() {
      byte[] samTNum = new byte[3];
      System.arraycopy(cardResponse, offset + 17, samTNum, 0, 3);
      return ByteArrayUtil.extractInt(samTNum, 0, 3, false);
    }

    /**
     * Gets the object content as a Json string.
     *
     * @return A not empty string.
     * @since 2.0.0
     */
    @Override
    public String toString() {
      return "{\"amount\":"
          + getAmount()
          + ",\"balance\":"
          + getBalance()
          + ",\"loadDate\":\""
          + HexUtil.toHex(getLoadDate())
          + "\",\"loadTime\":\""
          + HexUtil.toHex(getLoadTime())
          + "\",\"freeBytes\":\""
          + HexUtil.toHex(getFreeData())
          + "\",\"kvc\":\""
          + HexUtil.toHex(getKvc())
          + "\",\"samId\":\""
          + HexUtil.toHex(getSamId())
          + "\",\"svTransactionNumber\":"
          + getSvTNum()
          + ",\"svSamTransactionNumber\":"
          + getSamTNum()
          + "}";
    }
  }

  /**
   * The local command context specific to each command.
   *
   * @since 2.3.2
   */
  static final class CommandContextDto {

    private final boolean isSecureSessionOpen;
    private final boolean isEncryptionActive;

    /**
     * Constructor.
     *
     * @param isSecureSessionOpen Is secure session open?
     * @param isEncryptionActive Is encryption active?
     * @since 2.3.2
     */
    CommandContextDto(boolean isSecureSessionOpen, boolean isEncryptionActive) {
      this.isSecureSessionOpen = isSecureSessionOpen;
      this.isEncryptionActive = isEncryptionActive;
    }

    /**
     * @return True if the secure session is open.
     * @since 2.3.2
     */
    boolean isSecureSessionOpen() {
      return isSecureSessionOpen;
    }

    /**
     * @return True if the encryption is active.
     * @since 2.3.2
     */
    boolean isEncryptionActive() {
      return isEncryptionActive;
    }
  }

  /**
   * The global transaction context common to all commands.
   *
   * @since 2.3.2
   */
  static final class TransactionContextDto {

    private CalypsoCardAdapter card;
    private final SymmetricCryptoCardTransactionManagerSpi symmetricCryptoCardTransactionManagerSpi;
    private final AsymmetricCryptoCardTransactionManagerSpi
        asymmetricCryptoCardTransactionManagerSpi;
    private boolean isSecureSessionOpen;
    private final boolean isPkiMode;

    /**
     * Constructor for symmetric crypto operations.
     *
     * @param card The Calypso card.
     * @param symmetricCryptoCardTransactionManagerSpi The symmetric crypto service SPI.
     * @since 2.3.2
     */
    TransactionContextDto(
        CalypsoCardAdapter card,
        SymmetricCryptoCardTransactionManagerSpi symmetricCryptoCardTransactionManagerSpi) {
      this.card = card;
      this.symmetricCryptoCardTransactionManagerSpi = symmetricCryptoCardTransactionManagerSpi;
      this.asymmetricCryptoCardTransactionManagerSpi = null;
      isSecureSessionOpen = false;
      isPkiMode = false;
    }

    /**
     * Constructor for asymmetric crypto operations.
     *
     * @param card The Calypso card.
     * @param asymmetricCryptoCardTransactionManagerSpi The asymmetric crypto service SPI.
     * @since 3.1.0
     */
    TransactionContextDto(
        CalypsoCardAdapter card,
        AsymmetricCryptoCardTransactionManagerSpi asymmetricCryptoCardTransactionManagerSpi) {
      this.card = card;
      this.symmetricCryptoCardTransactionManagerSpi = null;
      this.asymmetricCryptoCardTransactionManagerSpi = asymmetricCryptoCardTransactionManagerSpi;
      isSecureSessionOpen = false;
      isPkiMode = true;
    }

    /**
     * Constructor for operations without cryptographic processes.
     *
     * @param card The Calypso card.
     * @since 3.1.0
     */
    public TransactionContextDto(CalypsoCardAdapter card) {
      this.card = card;
      this.symmetricCryptoCardTransactionManagerSpi = null;
      this.asymmetricCryptoCardTransactionManagerSpi = null;
      isSecureSessionOpen = false;
      isPkiMode = false;
    }

    /**
     * Constructor for operations outside an existing transaction.
     *
     * @since 3.1.0
     */
    public TransactionContextDto() {
      this.card = null;
      this.symmetricCryptoCardTransactionManagerSpi = null;
      this.asymmetricCryptoCardTransactionManagerSpi = null;
      isSecureSessionOpen = false;
      isPkiMode = false;
    }

    /**
     * @return The Calypso card.
     * @since 2.3.2
     */
    CalypsoCardAdapter getCard() {
      return card;
    }

    /**
     * @return The symmetric crypto service or "null" if not set.
     * @since 2.3.2
     */
    SymmetricCryptoCardTransactionManagerSpi getSymmetricCryptoCardTransactionManagerSpi() {
      return symmetricCryptoCardTransactionManagerSpi;
    }

    /**
     * @return The asymmetric crypto service or "null" if not set.
     * @since 3.1.0
     */
    AsymmetricCryptoCardTransactionManagerSpi getAsymmetricCryptoCardTransactionManagerSpi() {
      return asymmetricCryptoCardTransactionManagerSpi;
    }

    /**
     * @return "true" if the secure session is open.
     * @since 2.3.2
     */
    boolean isSecureSessionOpen() {
      return isSecureSessionOpen;
    }

    /**
     * @return "true" if the PKI mode is active.
     * @since 3.1.0
     */
    boolean isPkiMode() {
      return isPkiMode;
    }

    /**
     * Sets the Calypso card.
     *
     * @param card The Calypso card.
     * @since 3.0.0
     */
    void setCard(CalypsoCardAdapter card) {
      this.card = card;
    }

    /**
     * @param isSecureSessionOpen Is secure session open?
     * @since 2.3.2
     */
    void setSecureSessionOpen(boolean isSecureSessionOpen) {
      this.isSecureSessionOpen = isSecureSessionOpen;
    }
  }
}
