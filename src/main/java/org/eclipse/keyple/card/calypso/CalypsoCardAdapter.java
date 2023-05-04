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

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.card.*;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardSelectionResponseApi;
import org.calypsonet.terminal.card.spi.SmartCardSpi;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link CalypsoCard}.
 *
 * @since 2.0.0
 */
final class CalypsoCardAdapter implements CalypsoCard, SmartCardSpi {

  private static final Logger logger = LoggerFactory.getLogger(CalypsoCardAdapter.class);

  private static final String PATTERN_1_BYTE_HEX = "%02Xh";
  private static final String PATTERN_2_BYTES_HEX = "%04Xh";

  private static final int CARD_REV1_ATR_LENGTH = 20;
  private static final int REV1_CARD_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION = 3;
  private static final int REV2_CARD_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION = 6;
  private static final int SI_BUFFER_SIZE_INDICATOR = 0;
  private static final int SI_PLATFORM = 1;
  private static final int SI_APPLICATION_TYPE = 2;
  private static final int SI_APPLICATION_SUBTYPE = 3;
  private static final int SI_SOFTWARE_ISSUER = 4;
  private static final int SI_SOFTWARE_VERSION = 5;
  private static final int SI_SOFTWARE_REVISION = 6;
  private static final int DEFAULT_PAYLOAD_CAPACITY = 250;

  // Application type bitmasks features
  private static final byte APP_TYPE_WITH_CALYPSO_PIN = 0x01;
  private static final byte APP_TYPE_WITH_CALYPSO_SV = 0x02;
  private static final byte APP_TYPE_RATIFICATION_COMMAND_REQUIRED = 0x04;
  private static final byte APP_TYPE_CALYPSO_REV_32_MODE = 0x08;
  private static final byte APP_TYPE_WITH_PUBLIC_AUTHENTICATION = 0x10;

  // buffer indicator to buffer size lookup table
  private static final int[] BUFFER_SIZE_INDICATOR_TO_BUFFER_SIZE =
      new int[] {
        0, 0, 0, 0, 0, 0, 215, 256, 304, 362, 430, 512, 608, 724, 861, 1024, 1217, 1448, 1722, 2048,
        2435, 2896, 3444, 4096, 4870, 5792, 6888, 8192, 9741, 11585, 13777, 16384, 19483, 23170,
        27554, 32768, 38967, 46340, 55108, 65536, 77935, 92681, 110217, 131072, 155871, 185363,
        220435, 262144, 311743, 370727, 440871, 524288, 623487, 741455, 881743, 1048576
      };
  private ApduResponseApi selectApplicationResponse;
  private String powerOnData;
  private boolean isExtendedModeSupported;
  private boolean isRatificationOnDeselectSupported;
  private boolean isSvFeatureAvailable;
  private boolean isPinFeatureAvailable;
  private boolean isPkiModeSupported;
  private boolean isDfInvalidated;
  private CalypsoCardClass calypsoCardClass;
  private byte[] calypsoSerialNumber;
  private byte[] startupInfo;
  private ProductType productType = ProductType.UNKNOWN;
  private byte[] dfName;
  private int modificationsCounterMax;
  private boolean isModificationCounterInBytes = true;
  private DirectoryHeader directoryHeader;
  private final Set<ElementaryFile> files =
      Collections.newSetFromMap(new ConcurrentHashMap<ElementaryFile, Boolean>());
  private final Set<ElementaryFile> filesBackup =
      Collections.newSetFromMap(new ConcurrentHashMap<ElementaryFile, Boolean>());
  private ElementaryFileAdapter currentEf;
  private Boolean isDfRatified;
  private Integer transactionCounter;
  private Integer pinAttemptCounter;
  private Integer svBalance;
  private int svLastTNum;
  private Integer svBalanceBackup;
  private int svLastTNumBackup;
  private boolean isHce;
  private byte[] challenge;
  private byte[] traceabilityInformation;
  private byte svKvc;
  private byte[] svGetHeader;
  private byte[] svGetData;
  private byte[] svOperationSignature;
  private byte applicationSubType;
  private byte applicationType;
  private byte sessionModification;
  private int payloadCapacity = DEFAULT_PAYLOAD_CAPACITY;
  private boolean isCounterValuePostponed;
  private boolean isLegacyCase1;
  private WriteAccessLevel preOpenWriteAccessLevel;
  private byte[] preOpenDataOut;

  private static final List<PatchRev3> patchesRev3 = new ArrayList<PatchRev3>();
  private static final List<PatchRev12> patchesRev12 = new ArrayList<PatchRev12>();

  static {
    // Patches for revision 3:
    // XX 3C XX XX XX 10 XX
    patchesRev3.add(new PatchRev3("003C0000001000", "00FF000000FF00").setPayloadCapacity(235));

    // Patches for revision 1 & 2:
    // 06 XX 01 03 XX XX XX
    patchesRev12.add(new PatchRev12("06000103000000", "FF00FFFF000000").setCounterValuePostponed());
    // 06 0A 01 02 XX XX XX
    patchesRev12.add(new PatchRev12("060A0102000000", "FFFFFFFF000000").setCounterValuePostponed());
    // XX XX 0X XX 15 XX XX
    patchesRev12.add(new PatchRev12("00000000150000", "0000F000FF0000").setCounterValuePostponed());
    // XX XX 1X XX 15 XX XX
    patchesRev12.add(new PatchRev12("00001000150000", "0000F000FF0000").setCounterValuePostponed());
    // 03 08 03 04 00 02 00: targets ASK Tango having this startup info values
    patchesRev12.add(new PatchRev12("03080304000200", "FFFFFFFFFFFFFF").setLegacyCase1());
  }

  /**
   * Constructor.
   *
   * @since 2.0.0
   */
  CalypsoCardAdapter(CardSelectionResponseApi cardSelectionResponse) throws CardCommandException {
    if (cardSelectionResponse != null) {
      if (cardSelectionResponse.getSelectApplicationResponse() != null) {
        initializeWithFci(cardSelectionResponse.getSelectApplicationResponse());
      } else if (cardSelectionResponse.getPowerOnData() != null) {
        initializeWithPowerOnData(cardSelectionResponse.getPowerOnData());
      }
    }
  }

  /**
   * Initializes the object with the card power-on data.
   *
   * <p>This method should be invoked only when no response to select application is available.
   *
   * @param powerOnData The card's power-on data.
   * @throws IllegalArgumentException If powerOnData is inconsistent.
   */
  private void initializeWithPowerOnData(String powerOnData) {

    productType = ProductType.PRIME_REVISION_1;
    calypsoCardClass = CalypsoCardClass.LEGACY;

    this.powerOnData = powerOnData;

    // FCI is not provided: we consider it is Calypso card rev 1, it's serial number is provided in
    // the ATR
    byte[] atr = HexUtil.toByteArray(powerOnData);

    // basic check: we expect to be here following a selection based on the ATR
    if (atr.length != CARD_REV1_ATR_LENGTH) {
      throw new IllegalArgumentException("Unexpected ATR length: " + powerOnData);
    }

    dfName = null;
    calypsoSerialNumber = new byte[8];
    // old cards have their modification counter expressed in number of commands
    // the array is initialized with 0 (cf. default value for primitive types)
    System.arraycopy(atr, 12, calypsoSerialNumber, 4, 4);
    modificationsCounterMax = REV1_CARD_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION;

    startupInfo = new byte[7];
    // create buffer size indicator
    startupInfo[0] = (byte) modificationsCounterMax;
    // create the startup info with the 6 bytes of the ATR from position 6
    System.arraycopy(atr, 6, startupInfo, 1, 6);

    isRatificationOnDeselectSupported = true;
  }

  /**
   * Initializes or post-initializes the object with the application FCI data.
   *
   * @param selectApplicationResponse The select application response.
   * @throws IllegalArgumentException If the FCI is inconsistent.
   * @since 2.0.0
   */
  private void initializeWithFci(ApduResponseApi selectApplicationResponse)
      throws CardCommandException {
    this.selectApplicationResponse = selectApplicationResponse;
    if (selectApplicationResponse.getDataOut().length == 0) {
      // No FCI provided. May be filled later with a Get Data response.
      return;
    }
    // Parse card FCI - to retrieve DF Name (AID), Serial Number, &amp; StartupInfo
    // CL-SEL-TLVSTRUC.1
    CmdCardGetDataFci cmdCardGetDataFci = new CmdCardGetDataFci(CalypsoCardClass.ISO);
    cmdCardGetDataFci.setApduResponseAndCheckStatus(selectApplicationResponse, this);

    if (!cmdCardGetDataFci.isValidCalypsoFCI()) {
      throw new IllegalArgumentException("Bad FCI format.");
    }
  }

  /**
   * Initializes or post-initializes the object with the application FCI data.
   *
   * @param cmdCardGetDataFci The command containing the parsed FCI data.
   * @throws IllegalArgumentException If the FCI is inconsistent.
   * @since 2.2.3
   */
  void initializeWithFci(CmdCardGetDataFci cmdCardGetDataFci) {

    isDfInvalidated = cmdCardGetDataFci.isDfInvalidated();

    // CL-SEL-DATA.1
    dfName = cmdCardGetDataFci.getDfName();
    calypsoSerialNumber = cmdCardGetDataFci.getApplicationSerialNumber();
    // CL-SI-OTHER.1
    startupInfo = cmdCardGetDataFci.getDiscretionaryData();

    // CL-SI-ATRFU.1
    // CL-SI-ATPRIME.1
    // CL-SI-ATB6B5.1
    // CL-SI-ATLIGHT.1
    // CL-SI-ATBASIC.1
    applicationType = startupInfo[SI_APPLICATION_TYPE];
    productType = computeProductType(applicationType & 0xFF);

    // CL-SI-ASRFU.1
    applicationSubType = startupInfo[SI_APPLICATION_SUBTYPE];
    if (applicationSubType == (byte) 0x00 || applicationSubType == (byte) 0xFF) {
      throw new IllegalArgumentException(
          "Unexpected application subtype: "
              + String.format(PATTERN_1_BYTE_HEX, applicationSubType));
    }
    sessionModification = startupInfo[SI_BUFFER_SIZE_INDICATOR];

    if (productType == ProductType.PRIME_REVISION_2) {
      calypsoCardClass = CalypsoCardClass.LEGACY;
      // old cards have their modification counter expressed in number of commands
      isModificationCounterInBytes = false;
      modificationsCounterMax = REV2_CARD_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION;
    } else if (productType == ProductType.BASIC) {
      // CL-SI-SMBASIC.1
      if (sessionModification < 0x04 || sessionModification > 0x37) {
        throw new IllegalArgumentException(
            "Wrong session modification value for a Basic type (should be between 04h and 37h): "
                + String.format(PATTERN_1_BYTE_HEX, sessionModification));
      }
      calypsoCardClass = CalypsoCardClass.ISO;
      isModificationCounterInBytes = false;
      modificationsCounterMax = 3; // TODO Verify this
    } else {
      calypsoCardClass = CalypsoCardClass.ISO;
      // session buffer size
      // CL-SI-SM.1
      if (sessionModification < (byte) 0x06 || sessionModification > (byte) 0x37) {
        throw new IllegalArgumentException(
            "Session modifications byte should be in range 06h to 47h. Was: "
                + String.format(PATTERN_1_BYTE_HEX, sessionModification));
      }
      modificationsCounterMax = BUFFER_SIZE_INDICATOR_TO_BUFFER_SIZE[sessionModification];
    }

    // CL-SI-ATOPT.1
    if (productType == ProductType.PRIME_REVISION_3) {
      isExtendedModeSupported = (applicationType & APP_TYPE_CALYPSO_REV_32_MODE) != 0;
      isRatificationOnDeselectSupported =
          (applicationType & APP_TYPE_RATIFICATION_COMMAND_REQUIRED) == 0;
      isPkiModeSupported = (applicationType & APP_TYPE_WITH_PUBLIC_AUTHENTICATION) != 0;
    }

    if (productType == ProductType.PRIME_REVISION_3
        || productType == ProductType.PRIME_REVISION_2) {
      isSvFeatureAvailable = (applicationType & APP_TYPE_WITH_CALYPSO_SV) != 0;
      isPinFeatureAvailable = (applicationType & APP_TYPE_WITH_CALYPSO_PIN) != 0;
    }

    isHce = (calypsoSerialNumber[3] & (byte) 0x80) == (byte) 0x80;

    applyPatchIfNeeded();
  }

  /**
   * Some cards have specific features that need to be taken into account. This method identifies
   * them and applies the necessary modifications.
   */
  private void applyPatchIfNeeded() {
    long startupInfoLong = ByteArrayUtil.extractLong(startupInfo, 0, startupInfo.length, false);
    if (productType == ProductType.PRIME_REVISION_3) {
      applyPatchIfNeededForRevision(patchesRev3, startupInfoLong);
    } else if (productType == ProductType.PRIME_REVISION_2
        || productType == ProductType.PRIME_REVISION_1) {
      payloadCapacity = 128;
      applyPatchIfNeededForRevision(patchesRev12, startupInfoLong);
    }
  }

  private void applyPatchIfNeededForRevision(List<? extends Patch> patches, long startupInfoLong) {
    for (Patch patch : patches) {
      if (patch.isApplicableTo(startupInfoLong)) {
        patch.apply(this);
        return;
      }
    }
  }

  /**
   * Resolve the card product type from the application type byte
   *
   * @param applicationType The application type (field of startup info).
   * @return The product type.
   */
  private ProductType computeProductType(int applicationType) {
    if (applicationType == 0) {
      throw new IllegalArgumentException("Invalid application type 00h");
    }
    if (applicationType == 0xFF) {
      return ProductType.UNKNOWN;
    }
    if (applicationType <= 0x1F) {
      return ProductType.PRIME_REVISION_2;
    }
    if (applicationType >= 0x90 && applicationType <= 0x97) {
      return ProductType.LIGHT;
    }
    if (applicationType >= 0x98 && applicationType <= 0x9F) {
      return ProductType.BASIC;
    }
    return ProductType.PRIME_REVISION_3;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public ProductType getProductType() {
    return productType;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isHce() {
    return isHce;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isDfInvalidated() {
    return isDfInvalidated;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] getDfName() {
    return dfName;
  }

  /**
   * Gets the full Calypso serial number including the possible validity date information in the two
   * MSB.
   *
   * <p>The serial number to be used as diversifier for key derivation.<br>
   * This is the complete number returned by the card in its response to the Select command.
   *
   * @return A byte array containing the Calypso Serial Number (8 bytes)
   * @since 2.0.0
   */
  byte[] getCalypsoSerialNumberFull() {
    return calypsoSerialNumber;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] getApplicationSerialNumber() {
    byte[] applicationSerialNumber = calypsoSerialNumber.clone();
    applicationSerialNumber[0] = 0;
    applicationSerialNumber[1] = 0;
    return applicationSerialNumber;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] getStartupInfoRawData() {
    return startupInfo;
  }

  /**
   * Gets the maximum length of data that an APDU in this card can carry.
   *
   * @return An int
   * @since 2.0.0
   */
  int getPayloadCapacity() {
    return payloadCapacity;
  }

  /**
   * Tells if the change counter allowed in session is established in number of operations or number
   * of bytes modified.
   *
   * <p>This varies depending on the product type of the card.
   *
   * @return True if the counter is number of bytes
   * @since 2.0.0
   */
  boolean isModificationsCounterInBytes() {
    return isModificationCounterInBytes;
  }

  /**
   * Indicates the maximum number of changes allowed in session.
   *
   * <p>This number can be a number of operations or a number of commands (see
   * isModificationsCounterInBytes)
   *
   * @return The maximum number of modifications allowed
   * @since 2.0.0
   */
  int getModificationsCounter() {
    return modificationsCounterMax;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte getPlatform() {
    return startupInfo[SI_PLATFORM];
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte getApplicationType() {
    return applicationType;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isExtendedModeSupported() {
    return isExtendedModeSupported;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isRatificationOnDeselectSupported() {
    return isRatificationOnDeselectSupported;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isSvFeatureAvailable() {
    return isSvFeatureAvailable;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isPinFeatureAvailable() {
    return isPinFeatureAvailable;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isPkiModeSupported() {
    return isPkiModeSupported;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte getApplicationSubtype() {
    return applicationSubType;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte getSoftwareIssuer() {
    return startupInfo[SI_SOFTWARE_ISSUER];
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte getSoftwareVersion() {
    return startupInfo[SI_SOFTWARE_VERSION];
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte getSoftwareRevision() {
    return startupInfo[SI_SOFTWARE_REVISION];
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte getSessionModification() {
    return sessionModification;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public byte[] getTraceabilityInformation() {
    return traceabilityInformation != null ? traceabilityInformation : new byte[0];
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isDfRatified() {
    if (isDfRatified != null) {
      return isDfRatified;
    }
    throw new IllegalStateException(
        "Unable to determine the ratification status. No session was opened.");
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.1
   */
  @Override
  public int getTransactionCounter() {
    if (transactionCounter == null) {
      throw new IllegalStateException(
          "Unable to determine the transaction counter. No session was opened.");
    }
    return transactionCounter;
  }

  /**
   * Sets the Stored Value data from the SV Get command
   *
   * @param svKvc The KVC value.
   * @param svGetHeader A not empty array.
   * @param svGetData A not empty array.
   * @param svBalance the current SV balance.
   * @param svLastTNum the last SV transaction number.
   * @since 2.0.0
   */
  void setSvData(byte svKvc, byte[] svGetHeader, byte[] svGetData, int svBalance, int svLastTNum) {
    this.svKvc = svKvc;
    this.svGetHeader = svGetHeader;
    this.svGetData = svGetData;
    this.svBalance = svBalance;
    this.svLastTNum = svLastTNum;
  }

  /**
   * Updates the Stored Value data from the SV Get command
   *
   * @param svBalance the current SV balance.
   * @param svLastTNum the last SV transaction number.
   * @since 2.3.3
   */
  void updateSvData(int svBalance, int svLastTNum) {
    this.svBalance = svBalance;
    this.svLastTNum = svLastTNum;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public int getSvBalance() {
    if (svBalance == null) {
      throw new IllegalStateException("No SV Get command has been executed.");
    }
    return svBalance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public int getSvLastTNum() {
    if (svBalance == null) {
      throw new IllegalStateException("No SV Get command has been executed.");
    }
    return svLastTNum;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public SvLoadLogRecord getSvLoadLogRecord() {
    // try to get it from the file data
    ElementaryFile ef = getFileBySfi(CalypsoCardConstant.SV_RELOAD_LOG_FILE_SFI);
    if (ef != null) {
      byte[] logRecord = ef.getData().getContent();
      return new SvLoadLogRecordAdapter(logRecord, 0);
    }
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public SvDebitLogRecord getSvDebitLogLastRecord() {
    // try to get it from the file data
    List<SvDebitLogRecord> svDebitLogRecords = getSvDebitLogAllRecords();
    if (!svDebitLogRecords.isEmpty()) {
      return svDebitLogRecords.get(0);
    }
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public List<SvDebitLogRecord> getSvDebitLogAllRecords() {
    List<SvDebitLogRecord> svDebitLogRecords = new ArrayList<SvDebitLogRecord>();
    // get the logs from the file data
    ElementaryFile ef = getFileBySfi(CalypsoCardConstant.SV_DEBIT_LOG_FILE_SFI);
    if (ef == null) {
      return svDebitLogRecords;
    }
    SortedMap<Integer, byte[]> logRecords = ef.getData().getAllRecordsContent();
    for (Map.Entry<Integer, byte[]> entry : logRecords.entrySet()) {
      svDebitLogRecords.add(new SvDebitLogRecordAdapter(entry.getValue(), 0));
    }
    return svDebitLogRecords;
  }

  /**
   * Sets the ratification status
   *
   * @param dfRatified true if the session was ratified.
   * @since 2.0.0
   */
  void setDfRatified(boolean dfRatified) {
    isDfRatified = dfRatified;
  }

  /**
   * Sets the transaction counter.
   *
   * @param transactionCounter The counter value.
   * @since 2.1.1
   */
  void setTransactionCounter(int transactionCounter) {
    this.transactionCounter = transactionCounter;
  }

  /**
   * Gets the current card class.
   *
   * @return A not null reference.
   * @since 2.0.0
   */
  CalypsoCardClass getCardClass() {
    return calypsoCardClass;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public DirectoryHeader getDirectoryHeader() {
    return directoryHeader;
  }

  /**
   * Sets the DF metadata.<br>
   * Updates the invalidation flag.
   *
   * @param directoryHeader the DF metadata (should be not null).
   * @return the current instance.
   * @since 2.0.0
   */
  CalypsoCard setDirectoryHeader(DirectoryHeader directoryHeader) {
    this.directoryHeader = directoryHeader;
    this.isDfInvalidated = (directoryHeader.getDfStatus() & (byte) 0x01) != 0;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public ElementaryFile getFileBySfi(byte sfi) {
    if (sfi == 0) {
      return null;
    }
    for (ElementaryFile ef : files) {
      if (ef.getSfi() == sfi) {
        return ef;
      }
    }
    String sfiHex = String.format(PATTERN_1_BYTE_HEX, sfi);
    logger.warn("EF with SFI {} is not found.", sfiHex);
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public ElementaryFile getFileByLid(short lid) {
    for (ElementaryFile ef : files) {
      if (ef.getHeader() != null && ef.getHeader().getLid() == lid) {
        return ef;
      }
    }
    String lidHex = String.format(PATTERN_2_BYTES_HEX, lid);
    logger.warn("EF with LID {} is not found.", lidHex);
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Override
  @Deprecated
  public Map<Byte, ElementaryFile> getAllFiles() {
    Map<Byte, ElementaryFile> res = new HashMap<Byte, ElementaryFile>(files.size());
    for (ElementaryFile ef : files) {
      if (ef.getSfi() != 0) {
        res.put(ef.getSfi(), ef);
      }
    }
    return res;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public Set<ElementaryFile> getFiles() {
    return files;
  }

  /**
   * Returns a reference to the currently selected EF.<br>
   * If the file having the provided non-zero SFI or LID does not exist, then a new EF is created.
   * <br>
   * If the SFI and LID are both equal to 0, then the previously selected EF is returned.
   *
   * @param sfi The SFI (0 if not specified in the current command).
   * @param lid The LID (0 if not specified in the current command).
   * @return a not null reference.
   */
  private ElementaryFileAdapter getOrCreateFile(byte sfi, short lid) {
    if (sfi == 0 && lid == 0 && currentEf != null) {
      return currentEf;
    }
    if (sfi != 0) {
      // Search by SFI
      for (ElementaryFile ef : files) {
        if (ef.getSfi() == sfi) {
          currentEf = (ElementaryFileAdapter) ef;
          return currentEf;
        }
      }
    } else if (lid != 0) {
      // Search by LID
      for (ElementaryFile ef : files) {
        if (ef.getHeader() != null && ef.getHeader().getLid() == lid) {
          currentEf = (ElementaryFileAdapter) ef;
          return currentEf;
        }
      }
    }
    // Create a new EF with the provided SFI
    currentEf = new ElementaryFileAdapter(sfi);
    files.add(currentEf);
    return currentEf;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isPinBlocked() {
    return getPinAttemptRemaining() == 0;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public int getPinAttemptRemaining() {
    if (pinAttemptCounter == null) {
      throw new IllegalStateException("PIN status has not been checked.");
    }
    return pinAttemptCounter;
  }

  /**
   * Sets the PIN attempts counter.<br>
   * The PIN attempt counter is interpreted to give the results of the methods {@link #isPinBlocked}
   * and {@link #getPinAttemptRemaining}.
   *
   * @param pinAttemptCounter the number of remaining attempts to present the PIN code.
   * @since 2.0.0
   */
  void setPinAttemptRemaining(int pinAttemptCounter) {
    this.pinAttemptCounter = pinAttemptCounter;
  }

  /**
   * Sets the provided {@link FileHeaderAdapter} to the current selected file.<br>
   * If EF does not exist, then it is created.
   *
   * @param sfi the SFI.
   * @param header the file header (should be not null).
   * @since 2.0.0
   */
  void setFileHeader(byte sfi, FileHeaderAdapter header) {
    ElementaryFileAdapter ef = getOrCreateFile(sfi, header.getLid());
    if (ef.getHeader() == null) {
      ef.setHeader(header);
    } else {
      ef.getHeader().updateMissingInfoFrom(header);
    }
  }

  /**
   * Set or replace the entire content of the specified record #numRecord of the current selected
   * file by the provided content.<br>
   * If EF does not exist, then it is created.
   *
   * @param sfi the SFI.
   * @param numRecord the record number (should be {@code >=} 1).
   * @param content the content (should be not empty).
   * @since 2.0.0
   */
  void setContent(byte sfi, int numRecord, byte[] content) {
    ElementaryFileAdapter ef = getOrCreateFile(sfi, (short) 0);
    ef.getData().setContent(numRecord, content);
  }

  /**
   * Sets a counter value in record #1 of the current selected file.<br>
   * If EF does not exist, then it is created.
   *
   * @param sfi the SFI.
   * @param numCounter the counter number (should be {@code >=} 1).
   * @param content the counter value (should be not null and 3 bytes length).
   * @since 2.0.0
   */
  void setCounter(byte sfi, int numCounter, byte[] content) {
    ElementaryFileAdapter ef = getOrCreateFile(sfi, (short) 0);
    ef.getData().setCounter(numCounter, content);
  }

  /**
   * Set or replace the content at the specified offset of record #numRecord of the current selected
   * file by a copy of the provided content.<br>
   * If EF does not exist, then it is created.<br>
   * If actual record content is not set or has a size {@code <} offset, then missing data will be
   * padded with 0.
   *
   * @param sfi the SFI.
   * @param numRecord the record number (should be {@code >=} 1).
   * @param content the content (should be not empty).
   * @param offset the offset (should be {@code >=} 0).
   * @since 2.0.0
   */
  void setContent(byte sfi, int numRecord, byte[] content, int offset) {
    ElementaryFileAdapter ef = getOrCreateFile(sfi, (short) 0);
    ef.getData().setContent(numRecord, content, offset);
  }

  /**
   * Fills the content at the specified offset of the specified record of the current selected file
   * using a binary OR operation with the provided content.<br>
   * If EF does not exist, then it is created.<br>
   * If actual record content is not set or has a size {@code <} offset + content size, then missing
   * data will be completed by the provided content.
   *
   * @param sfi the SFI.
   * @param numRecord the record number (should be {@code >=} 1).
   * @param content the content (should be not empty).
   * @since 2.1.0
   */
  void fillContent(byte sfi, int numRecord, byte[] content, int offset) {
    ElementaryFileAdapter ef = getOrCreateFile(sfi, (short) 0);
    ef.getData().fillContent(numRecord, content, offset);
  }

  /**
   * Add cyclic content at record #1 by rolling previously all actual records contents (record #1 ->
   * record #2, record #2 -> record #3,...) of the current selected file.<br>
   * This is useful for cyclic files. Note that records are infinitely shifted.<br>
   * <br>
   * If EF does not exist, then it is created.
   *
   * @param sfi the SFI.
   * @param content the content (should be not empty).
   * @since 2.0.0
   */
  void addCyclicContent(byte sfi, byte[] content) {
    ElementaryFileAdapter ef = getOrCreateFile(sfi, (short) 0);
    ef.getData().addCyclicContent(content);
  }

  /**
   * Make a backup of the Elementary Files.<br>
   * This method should be used before starting a card secure session.
   *
   * @since 2.0.0
   */
  void backupFiles() {
    copyFiles(files, filesBackup);
    svBalanceBackup = svBalance;
    svLastTNumBackup = svLastTNum;
  }

  /**
   * Restore the last backup of Elementary Files.<br>
   * This method should be used when SW of the card close secure session command is unsuccessful or
   * if secure session is aborted.
   *
   * @since 2.0.0
   */
  void restoreFiles() {
    copyFiles(filesBackup, files);
    svBalance = svBalanceBackup;
    svLastTNum = svLastTNumBackup;
  }

  /**
   * Copy a set of ElementaryFile to another one by cloning each element.
   *
   * @param src the source (should be not null).
   * @param dest the destination (should be not null).
   */
  private static void copyFiles(Set<ElementaryFile> src, Set<ElementaryFile> dest) {
    dest.clear();
    for (ElementaryFile file : src) {
      dest.add(new ElementaryFileAdapter(file));
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getPowerOnData() {
    return powerOnData;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] getSelectApplicationResponse() {
    if (selectApplicationResponse == null) {
      return new byte[0];
    }
    return selectApplicationResponse.getApdu();
  }

  /**
   * Sets the challenge received in response to the GET CHALLENGE command.
   *
   * @param challenge A not empty array.
   * @since 2.0.0
   */
  void setChallenge(byte[] challenge) {
    this.challenge = challenge;
  }

  /**
   * Sets the traceability information received in response to the GET DATA command for the tag
   * {@link org.calypsonet.terminal.calypso.GetDataTag#TRACEABILITY_INFORMATION}.
   *
   * @param traceabilityInformation The traceability information.
   * @since 2.1.0
   */
  void setTraceabilityInformation(byte[] traceabilityInformation) {
    this.traceabilityInformation = traceabilityInformation;
  }

  /**
   * Sets the SV signature.
   *
   * @param svOperationSignature A not empty array.
   * @since 2.0.0
   */
  void setSvOperationSignature(byte[] svOperationSignature) {
    this.svOperationSignature = svOperationSignature;
  }

  /**
   * Gets the challenge received from the card
   *
   * @return An array of bytes containing the challenge bytes (variable length according to the
   *     product type of the card). May be null if the challenge is not available.
   * @since 2.0.0
   */
  byte[] getChallenge() {
    return challenge;
  }

  /**
   * Gets the SV KVC from the card
   *
   * @return The SV KVC byte.
   * @since 2.0.0
   */
  byte getSvKvc() {
    return svKvc;
  }

  /**
   * Gets the SV Get command header
   *
   * @return A byte array containing the SV Get command header.
   * @throws IllegalStateException If the requested data has not been set.
   * @since 2.0.0
   */
  byte[] getSvGetHeader() {
    if (svGetHeader == null) {
      throw new IllegalStateException("SV Get Header not available.");
    }
    return svGetHeader;
  }

  /**
   * Gets the SV Get command response data
   *
   * @return A byte array containing the SV Get command response data.
   * @throws IllegalStateException If the requested data has not been set.
   * @since 2.0.0
   */
  byte[] getSvGetData() {
    if (svGetData == null) {
      throw new IllegalStateException("SV Get Data not available.");
    }
    return svGetData;
  }

  /**
   * Gets the last SV Operation signature (SV Reload, Debit or Undebit)
   *
   * @return A byte array containing the SV Operation signature or null if not available.
   * @since 2.0.0
   */
  byte[] getSvOperationSignature() {
    return svOperationSignature;
  }

  /**
   * Indicates if the response of the Increase/Decrease counter command is postponed to the close
   * secure session (old revision 2 cards).
   *
   * @return true if the response of the Increase/Decrease counter command is postponed.
   * @since 2.2.4
   */
  boolean isCounterValuePostponed() {
    return isCounterValuePostponed;
  }

  /**
   * Indicates if the card is of a type corresponding to the specific case 1.
   *
   * @return true if the card corresponds to the specific case 1, false otherwise.
   * @see #patchesRev12
   * @since 2.3.5
   */
  boolean isLegacyCase1() {
    return isLegacyCase1;
  }

  /**
   * Disables extended mode. Although the card is in revision 3.2, it has indicated in response to
   * the "Open Secure Session" command that it does not use AES keys.
   *
   * @since 2.3.1
   */
  void disableExtendedMode() {
    isExtendedModeSupported = false;
  }

  WriteAccessLevel getPreOpenWriteAccessLevel() {
    return preOpenWriteAccessLevel;
  }

  CalypsoCardAdapter setPreOpenWriteAccessLevel(WriteAccessLevel preOpenWriteAccessLevel) {
    this.preOpenWriteAccessLevel = preOpenWriteAccessLevel;
    return this;
  }

  byte[] getPreOpenDataOut() {
    return preOpenDataOut;
  }

  CalypsoCardAdapter setPreOpenDataOut(byte[] preOpenDataOut) {
    this.preOpenDataOut = preOpenDataOut;
    return this;
  }

  /**
   * Gets the object content as a Json string.
   *
   * @return A not empty string.
   * @since 2.0.0
   */
  @Override
  public String toString() {
    return JsonUtil.toJson(this);
  }

  /** POJO containing card specificities to be applied according to startup info. */
  private abstract static class Patch {

    private final long startupInfo;
    private final Long mask;

    private Patch(String startupInfo) {
      this.startupInfo = HexUtil.toLong(startupInfo);
      this.mask = null;
    }

    private Patch(String startupInfo, String mask) {
      this.startupInfo = HexUtil.toLong(startupInfo);
      this.mask = HexUtil.toLong(mask);
    }

    private boolean isApplicableTo(long startupInfo) {
      return mask == null
          ? this.startupInfo == startupInfo
          : this.startupInfo == (startupInfo & mask);
    }

    abstract void apply(CalypsoCardAdapter calypsoCard);
  }

  /** POJO containing card rev 3 specificities to be applied according to startup info. */
  private static class PatchRev3 extends Patch {

    private Integer payloadCapacity;

    private PatchRev3(String startupInfo) {
      super(startupInfo);
    }

    private PatchRev3(String startupInfo, String mask) {
      super(startupInfo, mask);
    }

    @Override
    void apply(CalypsoCardAdapter calypsoCard) {
      if (payloadCapacity != null) {
        calypsoCard.payloadCapacity = payloadCapacity;
      }
    }

    private PatchRev3 setPayloadCapacity(Integer payloadCapacity) {
      this.payloadCapacity = payloadCapacity;
      return this;
    }
  }

  /** POJO containing card rev 1 & 2 specificities to be applied according to startup info. */
  private static class PatchRev12 extends Patch {

    private Boolean isCounterValuePostponed;
    private Boolean isLegacyCase1;

    private PatchRev12(String startupInfo) {
      super(startupInfo);
    }

    private PatchRev12(String startupInfo, String mask) {
      super(startupInfo, mask);
    }

    @Override
    void apply(CalypsoCardAdapter calypsoCard) {
      if (isCounterValuePostponed != null) {
        calypsoCard.isCounterValuePostponed = isCounterValuePostponed;
      }
      if (isLegacyCase1 != null) {
        calypsoCard.isLegacyCase1 = isLegacyCase1;
      }
    }

    private PatchRev12 setCounterValuePostponed() {
      isCounterValuePostponed = true;
      return this;
    }

    private PatchRev12 setLegacyCase1() {
      isLegacyCase1 = true;
      return this;
    }
  }
}
