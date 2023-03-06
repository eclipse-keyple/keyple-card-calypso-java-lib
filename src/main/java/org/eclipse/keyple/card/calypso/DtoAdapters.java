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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.calypsonet.terminal.calypso.card.SvDebitLogRecord;
import org.calypsonet.terminal.calypso.card.SvLoadLogRecord;
import org.calypsonet.terminal.calypso.transaction.BasicSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.BasicSignatureVerificationData;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureVerificationData;
import org.calypsonet.terminal.calypso.transaction.SearchCommandData;
import org.calypsonet.terminal.calypso.transaction.TraceableSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.TraceableSignatureVerificationData;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.calypsonet.terminal.card.spi.CardSelectionRequestSpi;
import org.calypsonet.terminal.card.spi.CardSelectorSpi;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;

class DtoAdapters {

  private static final String MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED =
      "The command has not yet been processed";

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
    public ApduRequestAdapter(byte[] apdu) {
      this.apdu = apdu;
      this.successfulStatusWords = new HashSet<Integer>();
      this.successfulStatusWords.add(DEFAULT_SUCCESSFUL_CODE);
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
    public ApduRequestAdapter addSuccessfulStatusWord(int successfulStatusWord) {
      this.successfulStatusWords.add(successfulStatusWord);
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
    public ApduRequestAdapter setInfo(final String info) {
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
      return this.apdu;
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
   * Implementation of {@link CommonSignatureComputationData}.
   *
   * @param <T> The type of the lowest level child object.
   * @since 2.2.0
   */
  abstract static class CommonSignatureComputationDataAdapter<
          T extends CommonSignatureComputationData<T>>
      implements CommonSignatureComputationData<T> {

    private final T currentInstance = (T) this;
    private byte[] data;
    private byte kif;
    private byte kvc;
    private int signatureSize = 8;
    private byte[] keyDiversifier;
    private byte[] signature;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    @Override
    public T setData(byte[] data, byte kif, byte kvc) {
      this.data = data;
      this.kif = kif;
      this.kvc = kvc;
      return currentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    @Override
    public T setSignatureSize(int size) {
      this.signatureSize = size;
      return currentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    @Override
    public T setKeyDiversifier(byte[] diversifier) {
      this.keyDiversifier = diversifier;
      return currentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    @Override
    public byte[] getSignature() {
      if (signature == null) {
        throw new IllegalStateException(MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED);
      }
      return signature;
    }

    /**
     * @return A not empty array of data. It is required to check input data first.
     * @since 2.2.0
     */
    byte[] getData() {
      return data;
    }

    /**
     * @return The KIF. It is required to check input data first.
     * @since 2.2.0
     */
    byte getKif() {
      return kif;
    }

    /**
     * @return The KVC. It is required to check input data first.
     * @since 2.2.0
     */
    byte getKvc() {
      return kvc;
    }

    /**
     * @return The signature size.
     * @since 2.2.0
     */
    int getSignatureSize() {
      return signatureSize;
    }

    /**
     * @return Null if the key diversifier is not set.
     * @since 2.2.0
     */
    byte[] getKeyDiversifier() {
      return keyDiversifier;
    }

    /**
     * Sets the computed signature.
     *
     * @param signature The computed signature.
     * @since 2.2.0
     */
    void setSignature(byte[] signature) {
      this.signature = signature;
    }
  }

  /**
   * Implementation of {@link CommonSignatureVerificationData}.
   *
   * @param <T> The type of the lowest level child object.
   * @since 2.2.0
   */
  abstract static class CommonSignatureVerificationDataAdapter<
          T extends CommonSignatureVerificationData<T>>
      implements CommonSignatureVerificationData<T> {

    private final T currentInstance = (T) this;
    private byte[] data;
    private byte[] signature;
    private byte kif;
    private byte kvc;
    private byte[] keyDiversifier;
    private Boolean isSignatureValid;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    @Override
    public T setData(byte[] data, byte[] signature, byte kif, byte kvc) {
      this.data = data;
      this.signature = signature;
      this.kif = kif;
      this.kvc = kvc;
      return currentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    @Override
    public T setKeyDiversifier(byte[] diversifier) {
      this.keyDiversifier = diversifier;
      return currentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    @Override
    public boolean isSignatureValid() {
      if (isSignatureValid == null) {
        throw new IllegalStateException(MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED);
      }
      return isSignatureValid;
    }

    /**
     * @return A not empty array of data. It is required to check input data first.
     * @since 2.2.0
     */
    byte[] getData() {
      return data;
    }

    /**
     * @return A not empty array of the signature to check. It is required to check input data
     *     first.
     * @since 2.2.0
     */
    byte[] getSignature() {
      return signature;
    }

    /**
     * @return The KIF. It is required to check input data first.
     * @since 2.2.0
     */
    byte getKif() {
      return kif;
    }

    /**
     * @return The KVC. It is required to check input data first.
     * @since 2.2.0
     */
    byte getKvc() {
      return kvc;
    }

    /**
     * @return Null if the key diversifier is not set.
     * @since 2.2.0
     */
    byte[] getKeyDiversifier() {
      return keyDiversifier;
    }

    /**
     * Sets the signature verification status.
     *
     * @param isSignatureValid True if the signature is valid.
     * @since 2.2.0
     */
    void setSignatureValid(boolean isSignatureValid) {
      this.isSignatureValid = isSignatureValid;
    }
  }

  /**
   * Implementation of {@link BasicSignatureComputationData}.
   *
   * @since 2.2.0
   */
  static class BasicSignatureComputationDataAdapter
      extends CommonSignatureComputationDataAdapter<BasicSignatureComputationData>
      implements BasicSignatureComputationData {}

  /**
   * Implementation of {@link BasicSignatureVerificationData}.
   *
   * @since 2.2.0
   */
  static class BasicSignatureVerificationDataAdapter
      extends CommonSignatureVerificationDataAdapter<BasicSignatureVerificationData>
      implements BasicSignatureVerificationData {}

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
    public CardRequestAdapter(
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
   * Implementation of {@link CardSelectorSpi}.
   *
   * @since 2.0.0
   */
  static final class CardSelectorAdapter implements CardSelectorSpi {

    private static final int DEFAULT_SUCCESSFUL_CODE = 0x9000;

    private String cardProtocol;
    private String powerOnDataRegex;
    private byte[] aid;
    private FileOccurrence fileOccurrence;
    private FileControlInformation fileControlInformation;
    private final Set<Integer> successfulSelectionStatusWords;

    /**
     * Created an instance of {@link CardSelectorAdapter}.
     *
     * <p>Initialize default values.
     *
     * @since 2.0.0
     */
    CardSelectorAdapter() {
      fileOccurrence = FileOccurrence.FIRST;
      fileControlInformation = FileControlInformation.FCI;
      successfulSelectionStatusWords = new LinkedHashSet<Integer>();
      successfulSelectionStatusWords.add(DEFAULT_SUCCESSFUL_CODE);
    }

    /**
     * Sets a protocol-based filtering by defining an expected card.
     *
     * <p>If the card protocol is set, only cards using that protocol will match the card selector.
     *
     * @param cardProtocol A not empty String.
     * @return The object instance.
     * @since 2.0.0
     */
    public CardSelectorSpi filterByCardProtocol(String cardProtocol) {
      this.cardProtocol = cardProtocol;
      return this;
    }

    /**
     * Sets a power-on data-based filtering by defining a regular expression that will be applied to
     * the card's power-on data.
     *
     * <p>If it is set, only the cards whose power-on data is recognized by the provided regular
     * expression will match the card selector.
     *
     * @param powerOnDataRegex A valid regular expression
     * @return The object instance.
     * @since 2.0.0
     */
    public CardSelectorSpi filterByPowerOnData(String powerOnDataRegex) {
      this.powerOnDataRegex = powerOnDataRegex;
      return this;
    }

    /**
     * Sets a DF Name-based filtering by defining in a byte array the AID that will be included in
     * the standard SELECT APPLICATION command sent to the card during the selection process.
     *
     * <p>The provided AID can be a right truncated image of the target DF Name (see ISO 7816-4
     * 4.2).
     *
     * @param aid A byte array containing 5 to 16 bytes.
     * @return The object instance.
     * @since 2.0.0
     */
    public CardSelectorSpi filterByDfName(byte[] aid) {
      this.aid = aid;
      return this;
    }

    /**
     * Sets a DF Name-based filtering by defining in a hexadecimal string the AID that will be
     * included in the standard SELECT APPLICATION command sent to the card during the selection
     * process.
     *
     * <p>The provided AID can be a right truncated image of the target DF Name (see ISO 7816-4
     * 4.2).
     *
     * @param aid A hexadecimal string representation of 5 to 16 bytes.
     * @return The object instance.
     * @since 2.0.0
     */
    public CardSelectorSpi filterByDfName(String aid) {
      return filterByDfName(HexUtil.toByteArray(aid));
    }

    /**
     * Sets the file occurrence mode (see ISO7816-4).
     *
     * <p>The default value is {@link FileOccurrence#FIRST}.
     *
     * @param fileOccurrence The {@link FileOccurrence}.
     * @return The object instance.
     * @since 2.0.0
     */
    public CardSelectorSpi setFileOccurrence(FileOccurrence fileOccurrence) {
      this.fileOccurrence = fileOccurrence;
      return this;
    }

    /**
     * Sets the file control mode (see ISO7816-4).
     *
     * <p>The default value is {@link FileControlInformation#FCI}.
     *
     * @param fileControlInformation The {@link FileControlInformation}.
     * @return The object instance.
     * @since 2.0.0
     */
    public CardSelectorSpi setFileControlInformation(
        FileControlInformation fileControlInformation) {
      this.fileControlInformation = fileControlInformation;
      return this;
    }

    /**
     * Adds a status word to the list of those that should be considered successful for the Select
     * Application APDU.
     *
     * <p>Note: initially, the list contains the standard successful status word {@code 9000h}.
     *
     * @param statusWord A positive int &le; {@code FFFFh}.
     * @return The object instance.
     * @since 2.0.0
     */
    public CardSelectorSpi addSuccessfulStatusWord(int statusWord) {
      this.successfulSelectionStatusWords.add(statusWord);
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public final String getCardProtocol() {
      return cardProtocol;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public String getPowerOnDataRegex() {
      return powerOnDataRegex;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public byte[] getAid() {
      return aid;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public FileOccurrence getFileOccurrence() {
      return fileOccurrence;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public FileControlInformation getFileControlInformation() {
      return fileControlInformation;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public Set<Integer> getSuccessfulSelectionStatusWords() {
      return successfulSelectionStatusWords;
    }
  }

  /**
   * This POJO contains the data used to define a selection case.
   *
   * <p>A selection case is defined by a {@link CardSelectorSpi} that target a particular smart card
   * and an optional {@link CardRequestSpi} containing additional APDU commands to be sent to the
   * card when the selection is successful.
   *
   * <p>One of the uses of this class is to open a logical communication channel with a card in
   * order to continue with other exchanges and carry out a complete transaction.
   *
   * @since 2.0.0
   */
  static final class CardSelectionRequestAdapter implements CardSelectionRequestSpi {

    private final CardSelectorSpi cardSelector;
    private final CardRequestSpi cardRequest;

    /**
     * Builds a card selection request to open a logical channel without sending additional APDUs.
     *
     * <p>The cardRequest field is set to null.
     *
     * @param cardSelector The card selector.
     * @since 2.0.0
     */
    public CardSelectionRequestAdapter(CardSelectorSpi cardSelector) {
      this(cardSelector, null);
    }

    /**
     * Builds a card selection request to open a logical channel with additional APDUs to be sent
     * after the selection step.
     *
     * @param cardSelector The card selector.
     * @param cardRequest The card request.
     * @since 2.0.0
     */
    public CardSelectionRequestAdapter(CardSelectorSpi cardSelector, CardRequestSpi cardRequest) {
      this.cardSelector = cardSelector;
      this.cardRequest = cardRequest;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public CardSelectorSpi getCardSelector() {
      return cardSelector;
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
   * Implementation of {@link TraceableSignatureComputationData}.
   *
   * @since 2.2.0
   */
  static final class TraceableSignatureComputationDataAdapter
      extends CommonSignatureComputationDataAdapter<TraceableSignatureComputationData>
      implements TraceableSignatureComputationData {

    private boolean isSamTraceabilityMode;
    private int traceabilityOffset;
    private boolean isPartialSamSerialNumber;
    private boolean isBusyMode = true;
    private byte[] signedData;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    @Override
    public TraceableSignatureComputationData withSamTraceabilityMode(
        int offset, boolean usePartialSamSerialNumber) {
      this.isSamTraceabilityMode = true;
      this.traceabilityOffset = offset;
      this.isPartialSamSerialNumber = usePartialSamSerialNumber;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    @Override
    public TraceableSignatureComputationData withoutBusyMode() {
      this.isBusyMode = false;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    @Override
    public byte[] getSignedData() {
      if (signedData == null) {
        throw new IllegalStateException(MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED);
      }
      return signedData;
    }

    /**
     * @return True if the "SAM traceability" mode is enabled.
     * @since 2.2.0
     */
    boolean isSamTraceabilityMode() {
      return isSamTraceabilityMode;
    }

    /**
     * @return The offset associated to the "SAM traceability" mode. It is required to check if the
     *     "SAM traceability" mode is enabled first.
     * @since 2.2.0
     */
    int getTraceabilityOffset() {
      return traceabilityOffset;
    }

    /**
     * @return True if it is requested to use the partial SAM serial number with the "SAM
     *     traceability" mode. It is required to check if the "SAM traceability" mode is enabled
     *     first.
     * @since 2.2.0
     */
    boolean isPartialSamSerialNumber() {
      return isPartialSamSerialNumber;
    }

    /**
     * @return True if the "Busy" mode is enabled.
     * @since 2.2.0
     */
    boolean isBusyMode() {
      return isBusyMode;
    }

    /**
     * Sets the data used for signature computation.
     *
     * @param signedData The signed data.
     * @since 2.2.0
     */
    void setSignedData(byte[] signedData) {
      this.signedData = signedData;
    }
  }

  /**
   * Implementation of {@link TraceableSignatureVerificationData}.
   *
   * @since 2.2.0
   */
  static final class TraceableSignatureVerificationDataAdapter
      extends CommonSignatureVerificationDataAdapter<TraceableSignatureVerificationData>
      implements TraceableSignatureVerificationData {

    private boolean isSamTraceabilityMode;
    private int traceabilityOffset;
    private boolean isPartialSamSerialNumber;
    private boolean isSamRevocationStatusVerificationRequested;
    private boolean isBusyMode = true;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    @Override
    public TraceableSignatureVerificationData withSamTraceabilityMode(
        int offset, boolean isPartialSamSerialNumber, boolean checkSamRevocationStatus) {
      this.isSamTraceabilityMode = true;
      this.traceabilityOffset = offset;
      this.isPartialSamSerialNumber = isPartialSamSerialNumber;
      this.isSamRevocationStatusVerificationRequested = checkSamRevocationStatus;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    @Override
    public TraceableSignatureVerificationData withoutBusyMode() {
      this.isBusyMode = false;
      return this;
    }

    /**
     * @return True if the "SAM traceability" mode is enabled.
     * @since 2.2.0
     */
    boolean isSamTraceabilityMode() {
      return isSamTraceabilityMode;
    }

    /**
     * @return The offset associated to the "SAM traceability" mode. It is required to check if the
     *     "SAM traceability" mode is enabled first.
     * @since 2.2.0
     */
    int getTraceabilityOffset() {
      return traceabilityOffset;
    }

    /**
     * @return True if it is requested to use the partial SAM serial number with the "SAM
     *     traceability" mode. It is required to check if the "SAM traceability" mode is enabled
     *     first.
     * @since 2.2.0
     */
    boolean isPartialSamSerialNumber() {
      return isPartialSamSerialNumber;
    }

    /**
     * @return True if the verification of the SAM revocation status is requested. It is required to
     *     check if the "SAM traceability" mode is enabled first.
     * @since 2.2.0
     */
    boolean isSamRevocationStatusVerificationRequested() {
      return isSamRevocationStatusVerificationRequested;
    }

    /**
     * @return True if the "Busy" mode is enabled.
     * @since 2.2.0
     */
    boolean isBusyMode() {
      return isBusyMode;
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
      this.enableRepeatedOffset = true;
      return this;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    @Override
    public SearchCommandData setSearchData(byte[] data) {
      this.searchData = data;
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
      this.fetchFirstMatchingResult = true;
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
  static class SvCommandSecurityDataApiAdapter implements SvCommandSecurityDataApi {

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
  static class SvDebitLogRecordAdapter implements SvDebitLogRecord {
    final int offset;
    final byte[] cardResponse;

    /**
     * Constructor
     *
     * @param cardResponse the Sv Get or Read Record (SV Load log file) response data.
     * @param offset the debit log offset in the response (may change from a card to another).
     */
    public SvDebitLogRecordAdapter(byte[] cardResponse, int offset) {
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
      final byte[] time = new byte[2];
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
      final byte[] date = new byte[2];
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
      final byte[] tnNum = new byte[2];
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
      StringBuilder sb = new StringBuilder();
      sb.append("{\"amount\":")
          .append(getAmount())
          .append(", \"balance\":")
          .append(getBalance())
          .append(", \"debitDate\": \"")
          .append(HexUtil.toHex(getDebitDate()))
          .append("\", \"debitTime\": \"")
          .append(HexUtil.toHex(getDebitTime()))
          .append("\", \"kvc\": \"")
          .append(HexUtil.toHex(getKvc()))
          .append("\", \"samId\": \"")
          .append(HexUtil.toHex(getSamId()))
          .append("\", \"svTransactionNumber\": ")
          .append(getSvTNum())
          .append(", \"svSamTransactionNumber\": ")
          .append(getSamTNum())
          .append("}");
      return sb.toString();
    }
  }

  /**
   * Implementation of {@link SvLoadLogRecord}.
   *
   * @since 2.0.0
   */
  static class SvLoadLogRecordAdapter implements SvLoadLogRecord {
    final int offset;
    final byte[] cardResponse;

    /**
     * Constructor
     *
     * @param cardResponse the Sv Get or Read Record (SV Debit log file) response data.
     * @param offset the load log offset in the response (may change from a card to another).
     * @since 2.0.0
     */
    public SvLoadLogRecordAdapter(byte[] cardResponse, int offset) {
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
      final byte[] time = new byte[2];
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
      final byte[] date = new byte[2];
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
      final byte[] free = new byte[2];
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
      final byte[] tnNum = new byte[2];
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
      StringBuilder sb = new StringBuilder();
      sb.append("{\"amount\":")
          .append(getAmount())
          .append(", \"balance\":")
          .append(getBalance())
          .append(", \"loadDate\": \"")
          .append(HexUtil.toHex(getLoadDate()))
          .append("\", \"loadTime\": \"")
          .append(HexUtil.toHex(getLoadTime()))
          .append("\", \"freeBytes\": \"")
          .append(HexUtil.toHex(getFreeData()))
          .append("\", \"kvc\": \"")
          .append(HexUtil.toHex(getKvc()))
          .append("\", \"samId\": \"")
          .append(HexUtil.toHex(getSamId()))
          .append("\", \"svTransactionNumber\": ")
          .append(getSvTNum())
          .append(", \"svSamTransactionNumber\": ")
          .append(getSamTNum())
          .append("}");
      return sb.toString();
    }
  }

  /**
   * The local command context specific to each command.
   *
   * @since 2.3.2
   */
  static class CommandContextDto {

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
     * @return "true" if the secure session is open.
     * @since 2.3.2
     */
    boolean isSecureSessionOpen() {
      return isSecureSessionOpen;
    }

    /**
     * @return "true" if the encryption is active.
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
  static class TransactionContextDto {

    private final CalypsoCardAdapter card;
    private final SymmetricCryptoTransactionManagerSpi symmetricCryptoTransactionManagerSpi;
    private boolean isSecureSessionOpen;

    /**
     * Constructor.
     *
     * @param card The Calypso card.
     * @param symmetricCryptoTransactionManagerSpi The symmetric crypto service SPI.
     * @since 2.3.2
     */
    public TransactionContextDto(
        CalypsoCardAdapter card,
        SymmetricCryptoTransactionManagerSpi symmetricCryptoTransactionManagerSpi) {
      this.card = card;
      this.symmetricCryptoTransactionManagerSpi = symmetricCryptoTransactionManagerSpi;
      this.isSecureSessionOpen = false;
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
    SymmetricCryptoTransactionManagerSpi getSymmetricCryptoTransactionManagerSpi() {
      return symmetricCryptoTransactionManagerSpi;
    }

    /**
     * @return "true" if the secure session is open.
     * @since 2.3.2
     */
    boolean isSecureSessionOpen() {
      return isSecureSessionOpen;
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
