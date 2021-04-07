/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://www.calypsonet-asso.org/
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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.eclipse.keyple.card.calypso.po.DirectoryHeader;
import org.eclipse.keyple.card.calypso.po.FileHeader;
import org.eclipse.keyple.card.calypso.po.SelectFileControl;
import org.eclipse.keyple.card.calypso.transaction.PoTransactionService;
import org.eclipse.keyple.core.card.ApduResponse;
import org.eclipse.keyple.core.util.Assert;

/**
 * (package-private)<br>
 * Utility class used to check Calypso specific data.
 *
 * <p>Helps the preparation and the analysis of Calypso Po commands.
 *
 * @since 2.0
 */
final class CalypsoPoUtils {
  public static final int MASK_3_BITS = 0x7; // 7
  public static final int MASK_4_BITS = 0xF; // 15
  public static final int MASK_5_BITS = 0x1F; // 31
  public static final int MASK_7_BITS = 0x7F; // 127
  public static final int MASK_1_BYTE = 0xFF; // 255
  public static final int MASK_2_BYTES = 0xFFFF;
  public static final int MASK_3_BYTES = 0xFFFFFF;

  // SFI
  public static final int SFI_MIN = 0;
  public static final int SFI_MAX = MASK_5_BITS;
  // Record number
  public static final int NB_REC_MIN = 1;
  public static final int NB_REC_MAX = 255;

  // Counter number
  public static final int NB_CNT_MIN = 1;
  public static final int NB_CNT_MAX = 255;

  // Counter value
  public static final int CNT_VALUE_MIN = 0;
  public static final int CNT_VALUE_MAX = 16777215;

  // Le max
  public static final int LE_MAX = 255;

  // File Type Values
  public static final int FILE_TYPE_MF = 1;
  public static final int FILE_TYPE_DF = 2;
  public static final int FILE_TYPE_EF = 4;

  // EF Type Values
  public static final int EF_TYPE_DF = 0;
  public static final int EF_TYPE_BINARY = 1;
  public static final int EF_TYPE_LINEAR = 2;
  public static final int EF_TYPE_CYCLIC = 4;
  public static final int EF_TYPE_SIMULATED_COUNTERS = 8;
  public static final int EF_TYPE_COUNTERS = 9;

  // Field offsets in select file response (tag/length excluded)
  public static final int SEL_SFI_OFFSET = 0;
  public static final int SEL_TYPE_OFFSET = 1;
  public static final int SEL_EF_TYPE_OFFSET = 2;
  public static final int SEL_REC_SIZE_OFFSET = 3;
  public static final int SEL_NUM_REC_OFFSET = 4;
  public static final int SEL_AC_OFFSET = 5;
  public static final int SEL_AC_LENGTH = 4;
  public static final int SEL_NKEY_OFFSET = 9;
  public static final int SEL_NKEY_LENGTH = 4;
  public static final int SEL_DF_STATUS_OFFSET = 13;
  public static final int SEL_KVCS_OFFSET = 14;
  public static final int SEL_KIFS_OFFSET = 17;
  public static final int SEL_DATA_REF_OFFSET = 14;
  public static final int SEL_LID_OFFSET = 21;

  public static final int PIN_LENGTH = 4;

  public static final byte STORED_VALUE_FILE_STRUCTURE_ID = (byte) 0x20;
  public static final byte SV_RELOAD_LOG_FILE_SFI = (byte) 0x14;
  public static final int SV_RELOAD_LOG_FILE_NB_REC = 1;
  public static final byte SV_DEBIT_LOG_FILE_SFI = (byte) 0x15;
  public static final int SV_DEBIT_LOG_FILE_NB_REC = 3;
  public static final int SV_LOG_FILE_REC_LENGTH = 29;

  private static byte[] poChallenge;
  private static byte svKvc;
  private static byte[] svGetHeader;
  private static byte[] svGetData;
  private static byte[] svOperationSignature;

  /** Private constructor */
  private CalypsoPoUtils() {}

  /**
   * Updates the {@link PoSmartCardAdapter} object with the response to a Open Secure Session
   * command received from the PO <br>
   * The ratification status and the data read at the time of the session opening are added to the
   * PoSmartCard.
   *
   * @param calypsoPoSmartCard the {@link PoSmartCardAdapter} object to update.
   * @param openSessionCmdBuild the Open Secure Session command builder.
   * @param apduResponse the response received.
   * @return the created response parser
   */
  private static AbstractPoOpenSessionParser updateCalypsoPoOpenSession(
      PoSmartCardAdapter calypsoPoSmartCard,
      AbstractPoOpenSessionBuilder<AbstractPoOpenSessionParser> openSessionCmdBuild,
      ApduResponse apduResponse) {
    // create parser
    AbstractPoOpenSessionParser openSessionRespPars =
        openSessionCmdBuild.createResponseParser(apduResponse);

    calypsoPoSmartCard.setDfRatified(openSessionRespPars.wasRatified());

    byte[] recordDataRead = openSessionRespPars.getRecordDataRead();

    if (recordDataRead.length > 0) {
      calypsoPoSmartCard.setContent(
          (byte) openSessionCmdBuild.getSfi(),
          openSessionCmdBuild.getRecordNumber(),
          recordDataRead);
    }

    return openSessionRespPars;
  }

  /**
   * Checks the response to a Close Session command
   *
   * @param poCloseSessionBuilder the Close Session command builder.
   * @param apduResponse the response received.
   * @return the created response parser
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static PoCloseSessionParser updateCalypsoPoCloseSession(
      PoCloseSessionBuilder poCloseSessionBuilder, ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    PoCloseSessionParser poCloseSessionParser =
        poCloseSessionBuilder.createResponseParser(apduResponse);

    poCloseSessionParser.checkStatus();

    return poCloseSessionParser;
  }

  /**
   * Updates the {@link PoSmartCardAdapter} object with the response to a Read Records command
   * received from the PO <br>
   * The records read are added to the {@link PoSmartCardAdapter} file structure
   *
   * @param calypsoPoSmartCard the {@link PoSmartCardAdapter} object to update.
   * @param poReadRecordsBuilder the Read Records command builder.
   * @param apduResponse the response received.
   * @return the created response parser
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static PoReadRecordsParser updateCalypsoPoReadRecords(
      PoSmartCardAdapter calypsoPoSmartCard,
      PoReadRecordsBuilder poReadRecordsBuilder,
      ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    // create parser
    PoReadRecordsParser poReadRecordsParser =
        poReadRecordsBuilder.createResponseParser(apduResponse);

    poReadRecordsParser.checkStatus();

    // iterate over read records to fill the PoSmartCard
    for (Map.Entry<Integer, byte[]> entry : poReadRecordsParser.getRecords().entrySet()) {
      calypsoPoSmartCard.setContent(
          (byte) poReadRecordsBuilder.getSfi(), entry.getKey(), entry.getValue());
    }
    return poReadRecordsParser;
  }

  /**
   * Updates the {@link PoSmartCardAdapter} object with the response to a Select File command
   * received from the PO <br>
   * Depending on the content of the response, either a {@link FileHeader} is added or the {@link
   * DirectoryHeader} is updated
   *
   * @param calypsoPoSmartCard the {@link PoSmartCardAdapter} object to update.
   * @param poSelectFileBuilder the Select File command builder.
   * @param apduResponse the response received.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static PoSelectFileParser updateCalypsoPoSelectFile(
      PoSmartCardAdapter calypsoPoSmartCard,
      PoSelectFileBuilder poSelectFileBuilder,
      ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    PoSelectFileParser poSelectFileParser = poSelectFileBuilder.createResponseParser(apduResponse);

    poSelectFileParser.checkStatus();

    byte[] proprietaryInformation = poSelectFileParser.getProprietaryInformation();
    byte sfi = proprietaryInformation[SEL_SFI_OFFSET];
    byte fileType = proprietaryInformation[SEL_TYPE_OFFSET];
    switch (fileType) {
      case FILE_TYPE_MF:
      case FILE_TYPE_DF:
        DirectoryHeader directoryHeader = createDirectoryHeader(proprietaryInformation);
        calypsoPoSmartCard.setDirectoryHeader(directoryHeader);
        break;
      case FILE_TYPE_EF:
        FileHeader fileHeader = createFileHeader(proprietaryInformation);
        calypsoPoSmartCard.setFileHeader(sfi, fileHeader);
        break;
      default:
        throw new IllegalStateException(String.format("Unknown file type: 0x%02X", fileType));
    }
    return poSelectFileParser;
  }

  /**
   * Updates the {@link PoSmartCardAdapter} object with the response to a Update Record command sent
   * and received from the PO <br>
   * The records read are added to the {@link PoSmartCardAdapter} file structure
   *
   * @param calypsoPoSmartCard the {@link PoSmartCardAdapter} object to update.
   * @param poUpdateRecordBuilder the Update Record command builder.
   * @param apduResponse the response received.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static PoUpdateRecordParser updateCalypsoPoUpdateRecord(
      PoSmartCardAdapter calypsoPoSmartCard,
      PoUpdateRecordBuilder poUpdateRecordBuilder,
      ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    PoUpdateRecordParser poUpdateRecordParser =
        poUpdateRecordBuilder.createResponseParser(apduResponse);

    poUpdateRecordParser.checkStatus();

    calypsoPoSmartCard.setContent(
        (byte) poUpdateRecordBuilder.getSfi(),
        poUpdateRecordBuilder.getRecordNumber(),
        poUpdateRecordBuilder.getData());

    return poUpdateRecordParser;
  }

  /**
   * Updates the {@link PoSmartCardAdapter} object with the response to a Write Record command sent
   * and received from the PO <br>
   * The records read are added to the {@link PoSmartCardAdapter} file structure using the dedicated
   * {@link PoSmartCardAdapter#fillContent } method.
   *
   * @param calypsoPoSmartCard the {@link PoSmartCardAdapter} object to update.
   * @param poWriteRecordBuilder the Write Record command builder.
   * @param apduResponse the response received.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static PoWriteRecordParser updateCalypsoPoWriteRecord(
      PoSmartCardAdapter calypsoPoSmartCard,
      PoWriteRecordBuilder poWriteRecordBuilder,
      ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    PoWriteRecordParser poWriteRecordParser =
        poWriteRecordBuilder.createResponseParser(apduResponse);

    poWriteRecordParser.checkStatus();

    calypsoPoSmartCard.fillContent(
        (byte) poWriteRecordBuilder.getSfi(),
        poWriteRecordBuilder.getRecordNumber(),
        poWriteRecordBuilder.getData());

    return poWriteRecordParser;
  }

  /**
   * Updates the {@link PoSmartCardAdapter} object with the response to a Read Records command
   * received from the PO <br>
   * The records read are added to the {@link PoSmartCardAdapter} file structure
   *
   * @param poAppendRecordBuilder the Append Records command builder.
   * @param calypsoPoSmartCard the {@link PoSmartCardAdapter} object to update.
   * @param apduResponse the response received.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static PoAppendRecordParser updateCalypsoPoAppendRecord(
      PoSmartCardAdapter calypsoPoSmartCard,
      PoAppendRecordBuilder poAppendRecordBuilder,
      ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    PoAppendRecordParser poAppendRecordParser =
        poAppendRecordBuilder.createResponseParser(apduResponse);

    poAppendRecordParser.checkStatus();

    calypsoPoSmartCard.addCyclicContent(
        (byte) poAppendRecordBuilder.getSfi(), poAppendRecordBuilder.getData());

    return poAppendRecordParser;
  }

  /**
   * Updates the {@link PoSmartCardAdapter} object with the response to a Decrease command received
   * from the PO <br>
   * The counter value is updated in the {@link PoSmartCardAdapter} file structure
   *
   * @param poDecreaseBuilder the Decrease command builder.
   * @param calypsoPoSmartCard the {@link PoSmartCardAdapter} object to update.
   * @param apduResponse the response received.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static PoDecreaseParser updateCalypsoPoDecrease(
      PoSmartCardAdapter calypsoPoSmartCard,
      PoDecreaseBuilder poDecreaseBuilder,
      ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    PoDecreaseParser poDecreaseParser = poDecreaseBuilder.createResponseParser(apduResponse);

    poDecreaseParser.checkStatus();

    calypsoPoSmartCard.setContent(
        (byte) poDecreaseBuilder.getSfi(),
        1,
        apduResponse.getDataOut(),
        3 * (poDecreaseBuilder.getCounterNumber() - 1));

    return poDecreaseParser;
  }

  /**
   * Updates the {@link PoSmartCardAdapter} object with the response to an Increase command received
   * from the PO <br>
   * The counter value is updated in the {@link PoSmartCardAdapter} file structure
   *
   * @param poIncreaseBuilder the Increase command builder.
   * @param calypsoPoSmartCard the {@link PoSmartCardAdapter} object to update.
   * @param apduResponse the response received.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static PoIncreaseParser updateCalypsoPoIncrease(
      PoSmartCardAdapter calypsoPoSmartCard,
      PoIncreaseBuilder poIncreaseBuilder,
      ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    PoIncreaseParser poIncreaseParser = poIncreaseBuilder.createResponseParser(apduResponse);

    poIncreaseParser.checkStatus();

    calypsoPoSmartCard.setContent(
        (byte) poIncreaseBuilder.getSfi(),
        1,
        apduResponse.getDataOut(),
        3 * (poIncreaseBuilder.getCounterNumber() - 1));

    return poIncreaseParser;
  }

  /**
   * Parses the response to a Get Challenge command received from the PO <br>
   * The PO challenge value is stored in {@link CalypsoPoUtils} and made available through a
   * dedicated getters for later use
   *
   * @param poGetChallengeBuilder the Get Challenge command builder.
   * @param apduResponse the response received.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static PoGetChallengeRespPars updateCalypsoPoGetChallenge(
      PoGetChallengeBuilder poGetChallengeBuilder, ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    PoGetChallengeRespPars poGetChallengeRespPars =
        poGetChallengeBuilder.createResponseParser(apduResponse);

    poGetChallengeRespPars.checkStatus();

    poChallenge = apduResponse.getDataOut();

    return poGetChallengeRespPars;
  }

  /**
   * Updates the {@link PoSmartCardAdapter} object with the response to an Verify Pin command
   * received from the PO <br>
   * The PIN attempt counter value is stored in the {@link PoSmartCardAdapter}<br>
   * CalypsoPoPinException are filtered when the initial command targets the reading of the attempt
   * counter.
   *
   * @param calypsoPoSmartCard the {@link PoSmartCardAdapter} object to update.
   * @param poVerifyPinBuilder the Verify PIN command builder.
   * @param apduResponse the response received.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static PoVerifyPinParser updateCalypsoVerifyPin(
      PoSmartCardAdapter calypsoPoSmartCard,
      PoVerifyPinBuilder poVerifyPinBuilder,
      ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    PoVerifyPinParser poVerifyPinParser = poVerifyPinBuilder.createResponseParser(apduResponse);

    calypsoPoSmartCard.setPinAttemptRemaining(poVerifyPinParser.getRemainingAttemptCounter());

    try {
      poVerifyPinParser.checkStatus();
    } catch (CalypsoPoPinException ex) {
      // forward the exception if the operation do not target the reading of the attempt
      // counter.
      // catch it silently otherwise
      if (!poVerifyPinBuilder.isReadCounterOnly()) {
        throw ex;
      }
    }

    return poVerifyPinParser;
  }

  /**
   * Updates the {@link PoSmartCardAdapter} object with the response to an SV Get command received
   * from the PO <br>
   * The SV Data values (KVC, command header, response data) are stored in {@link CalypsoPoUtils}
   * and made available through a dedicated getters for later use<br>
   *
   * @param calypsoPoSmartCard the {@link PoSmartCardAdapter} object to update.
   * @param poSvGetBuilder the SV Get command builder.
   * @param apduResponse the response received.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static PoSvGetParser updateCalypsoPoSvGet(
      PoSmartCardAdapter calypsoPoSmartCard,
      PoSvGetBuilder poSvGetBuilder,
      ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    PoSvGetParser poSvGetParser = poSvGetBuilder.createResponseParser(apduResponse);

    poSvGetParser.checkStatus();

    calypsoPoSmartCard.setSvData(
        poSvGetParser.getBalance(),
        poSvGetParser.getTransactionNumber(),
        poSvGetParser.getLoadLog(),
        poSvGetParser.getDebitLog());

    svKvc = poSvGetParser.getCurrentKVC();
    svGetHeader = poSvGetParser.getSvGetCommandHeader();
    svGetData = poSvGetParser.getApduResponse().getBytes();

    return poSvGetParser;
  }

  /**
   * Checks the response to a SV Operation command (reload, debit or undebit) response received from
   * the PO<br>
   * Keep the PO SV signature if any (command executed outside a secure session).
   *
   * @param svOperationCmdBuild the SV Operation command builder (PoSvReloadBuilder,
   *     PoSvDebitBuilder or PoSvUndebitBuilder)
   * @param apduResponse the response received.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static AbstractPoResponseParser updateCalypsoPoSvOperation(
      AbstractPoCommandBuilder<? extends AbstractPoResponseParser> svOperationCmdBuild,
      ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    AbstractPoResponseParser svOperationRespPars =
        svOperationCmdBuild.createResponseParser(apduResponse);

    svOperationRespPars.checkStatus();

    svOperationSignature = svOperationRespPars.getApduResponse().getDataOut();

    return svOperationRespPars;
  }

  /**
   * Checks the response to Invalidate/Rehabilitate commands
   *
   * @param invalidateRehabilitateCmdBuild the Invalidate or Rehabilitate response parser.
   * @param apduResponse the response received.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  private static AbstractPoResponseParser updateCalypsoInvalidateRehabilitate(
      AbstractPoCommandBuilder<? extends AbstractPoResponseParser> invalidateRehabilitateCmdBuild,
      ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    AbstractPoResponseParser invalidateRehabilitateRespPars =
        invalidateRehabilitateCmdBuild.createResponseParser(apduResponse);

    invalidateRehabilitateRespPars.checkStatus();

    return invalidateRehabilitateRespPars;
  }

  /**
   * Parses the proprietaryInformation field of a file identified as an DF and create a {@link
   * DirectoryHeader}
   *
   * @param proprietaryInformation from the response to a Select File command.
   * @return a {@link DirectoryHeader} object
   */
  private static DirectoryHeader createDirectoryHeader(byte[] proprietaryInformation) {
    byte[] accessConditions = new byte[SEL_AC_LENGTH];
    System.arraycopy(proprietaryInformation, SEL_AC_OFFSET, accessConditions, 0, SEL_AC_LENGTH);

    byte[] keyIndexes = new byte[SEL_NKEY_LENGTH];
    System.arraycopy(proprietaryInformation, SEL_NKEY_OFFSET, keyIndexes, 0, SEL_NKEY_LENGTH);

    byte dfStatus = proprietaryInformation[SEL_DF_STATUS_OFFSET];

    short lid =
        (short)
            (((proprietaryInformation[SEL_LID_OFFSET] << 8) & 0xff00)
                | (proprietaryInformation[SEL_LID_OFFSET + 1] & 0x00ff));

    return DirectoryHeaderAdapter.builder()
        .lid(lid)
        .accessConditions(accessConditions)
        .keyIndexes(keyIndexes)
        .dfStatus(dfStatus)
        .kvc(
            PoTransactionService.SessionAccessLevel.SESSION_LVL_PERSO,
            proprietaryInformation[SEL_KVCS_OFFSET])
        .kvc(
            PoTransactionService.SessionAccessLevel.SESSION_LVL_LOAD,
            proprietaryInformation[SEL_KVCS_OFFSET + 1])
        .kvc(
            PoTransactionService.SessionAccessLevel.SESSION_LVL_DEBIT,
            proprietaryInformation[SEL_KVCS_OFFSET + 2])
        .kif(
            PoTransactionService.SessionAccessLevel.SESSION_LVL_PERSO,
            proprietaryInformation[SEL_KIFS_OFFSET])
        .kif(
            PoTransactionService.SessionAccessLevel.SESSION_LVL_LOAD,
            proprietaryInformation[SEL_KIFS_OFFSET + 1])
        .kif(
            PoTransactionService.SessionAccessLevel.SESSION_LVL_DEBIT,
            proprietaryInformation[SEL_KIFS_OFFSET + 2])
        .build();
  }

  /**
   * Converts the EF type value from the PO into a {@link FileHeader.FileType} enum
   *
   * @param efType the value returned by the PO.
   * @return the corresponding {@link FileHeader.FileType}
   */
  private static FileHeader.FileType getEfTypeFromPoValue(byte efType) {
    FileHeader.FileType fileType;
    switch (efType) {
      case EF_TYPE_BINARY:
        fileType = FileHeader.FileType.BINARY;
        break;
      case EF_TYPE_LINEAR:
        fileType = FileHeader.FileType.LINEAR;
        break;
      case EF_TYPE_CYCLIC:
        fileType = FileHeader.FileType.CYCLIC;
        break;
      case EF_TYPE_SIMULATED_COUNTERS:
        fileType = FileHeader.FileType.SIMULATED_COUNTERS;
        break;
      case EF_TYPE_COUNTERS:
        fileType = FileHeader.FileType.COUNTERS;
        break;
      default:
        throw new IllegalStateException("Unknown EF Type: " + efType);
    }
    return fileType;
  }

  /**
   * Parses the proprietaryInformation field of a file identified as an EF and create a {@link
   * FileHeader}
   *
   * @param proprietaryInformation from the response to a Select File command.
   * @return a {@link FileHeader} object
   */
  private static FileHeader createFileHeader(byte[] proprietaryInformation) {

    FileHeader.FileType fileType = getEfTypeFromPoValue(proprietaryInformation[SEL_EF_TYPE_OFFSET]);

    int recordSize;
    int recordsNumber;
    if (fileType == FileHeader.FileType.BINARY) {
      recordSize =
          ((proprietaryInformation[SEL_REC_SIZE_OFFSET] << 8) & 0x0000ff00)
              | (proprietaryInformation[SEL_NUM_REC_OFFSET] & 0x000000ff);
      recordsNumber = 1;
    } else {
      recordSize = proprietaryInformation[SEL_REC_SIZE_OFFSET];
      recordsNumber = proprietaryInformation[SEL_NUM_REC_OFFSET];
    }

    byte[] accessConditions = new byte[SEL_AC_LENGTH];
    System.arraycopy(proprietaryInformation, SEL_AC_OFFSET, accessConditions, 0, SEL_AC_LENGTH);

    byte[] keyIndexes = new byte[SEL_NKEY_LENGTH];
    System.arraycopy(proprietaryInformation, SEL_NKEY_OFFSET, keyIndexes, 0, SEL_NKEY_LENGTH);

    byte dfStatus = proprietaryInformation[SEL_DF_STATUS_OFFSET];

    short sharedReference =
        (short)
            (((proprietaryInformation[SEL_DATA_REF_OFFSET] << 8) & 0xff00)
                | (proprietaryInformation[SEL_DATA_REF_OFFSET + 1] & 0x00ff));

    short lid =
        (short)
            (((proprietaryInformation[SEL_LID_OFFSET] << 8) & 0xff00)
                | (proprietaryInformation[SEL_LID_OFFSET + 1] & 0x00ff));

    return FileHeaderAdapter.builder()
        .lid(lid)
        .recordsNumber(recordsNumber)
        .recordSize(recordSize)
        .type(fileType)
        .accessConditions(Arrays.copyOf(accessConditions, accessConditions.length))
        .keyIndexes(Arrays.copyOf(keyIndexes, keyIndexes.length))
        .dfStatus(dfStatus)
        .sharedReference(sharedReference)
        .build();
  }

  /**
   * (package-private)<br>
   * Fills the PoSmartCard with the PO's response to a single command
   *
   * @param calypsoPoSmartCard the {@link PoSmartCardAdapter} object to fill with the. provided
   *     response from the PO
   * @param commandBuilder the builder of the command that get the response.
   * @param apduResponse the APDU response returned by the PO to the command.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  static AbstractPoResponseParser updateCalypsoPo(
      PoSmartCardAdapter calypsoPoSmartCard,
      AbstractPoCommandBuilder<? extends AbstractPoResponseParser> commandBuilder,
      ApduResponse apduResponse)
      throws CalypsoPoCommandException {
    switch (commandBuilder.getCommandRef()) {
      case READ_RECORDS:
        return updateCalypsoPoReadRecords(
            calypsoPoSmartCard, (PoReadRecordsBuilder) commandBuilder, apduResponse);
      case SELECT_FILE:
        return updateCalypsoPoSelectFile(
            calypsoPoSmartCard, (PoSelectFileBuilder) commandBuilder, apduResponse);
      case UPDATE_RECORD:
        return updateCalypsoPoUpdateRecord(
            calypsoPoSmartCard, (PoUpdateRecordBuilder) commandBuilder, apduResponse);
      case WRITE_RECORD:
        return updateCalypsoPoWriteRecord(
            calypsoPoSmartCard, (PoWriteRecordBuilder) commandBuilder, apduResponse);
      case APPEND_RECORD:
        return updateCalypsoPoAppendRecord(
            calypsoPoSmartCard, (PoAppendRecordBuilder) commandBuilder, apduResponse);
      case DECREASE:
        return updateCalypsoPoDecrease(
            calypsoPoSmartCard, (PoDecreaseBuilder) commandBuilder, apduResponse);
      case INCREASE:
        return updateCalypsoPoIncrease(
            calypsoPoSmartCard, (PoIncreaseBuilder) commandBuilder, apduResponse);
      case OPEN_SESSION_10:
      case OPEN_SESSION_24:
      case OPEN_SESSION_31:
      case OPEN_SESSION_32:
        return updateCalypsoPoOpenSession(
            calypsoPoSmartCard,
            (AbstractPoOpenSessionBuilder<AbstractPoOpenSessionParser>) commandBuilder,
            apduResponse);
      case CLOSE_SESSION:
        return updateCalypsoPoCloseSession((PoCloseSessionBuilder) commandBuilder, apduResponse);
      case GET_CHALLENGE:
        return updateCalypsoPoGetChallenge((PoGetChallengeBuilder) commandBuilder, apduResponse);
      case VERIFY_PIN:
        return updateCalypsoVerifyPin(
            calypsoPoSmartCard, (PoVerifyPinBuilder) commandBuilder, apduResponse);
      case SV_GET:
        return updateCalypsoPoSvGet(
            calypsoPoSmartCard, (PoSvGetBuilder) commandBuilder, apduResponse);
      case SV_RELOAD:
      case SV_DEBIT:
      case SV_UNDEBIT:
        return updateCalypsoPoSvOperation(commandBuilder, apduResponse);
      case INVALIDATE:
      case REHABILITATE:
        return updateCalypsoInvalidateRehabilitate(commandBuilder, apduResponse);
      case CHANGE_KEY:
      case GET_DATA_FCI:
      case GET_DATA_TRACE:
        throw new IllegalStateException("Shouldn't happen for now!");
      default:
        throw new IllegalStateException("Unknown command reference.");
    }
  }

  /**
   * (package-private)<br>
   * Fills the PoSmartCard with the PO's responses to a list of commands
   *
   * @param calypsoPoSmartCard the {@link PoSmartCardAdapter} object to fill with the. provided
   *     response from the PO
   * @param commandBuilders the list of builders that get the responses.
   * @param apduResponses the APDU responses returned by the PO to all commands.
   * @throws CalypsoPoCommandException if a response from the PO was unexpected
   */
  static void updateCalypsoPo(
      PoSmartCardAdapter calypsoPoSmartCard,
      List<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>> commandBuilders,
      List<ApduResponse> apduResponses)
      throws CalypsoPoCommandException {
    Iterator<ApduResponse> responseIterator = apduResponses.iterator();

    if (commandBuilders != null && !commandBuilders.isEmpty()) {
      for (AbstractPoCommandBuilder<? extends AbstractPoResponseParser> commandBuilder :
          commandBuilders) {
        ApduResponse apduResponse = responseIterator.next();
        updateCalypsoPo(calypsoPoSmartCard, commandBuilder, apduResponse);
      }
    }
  }

  /**
   * Create a Read Records command builder for the provided arguments
   *
   * @param poClass the class of the PO.
   * @param sfi the SFI of the EF to read.
   * @param recordNumber the record number to read.
   * @return a {@link PoReadRecordsBuilder} object
   * @throws IllegalArgumentException If one of the arguments is out of range.
   * @since 2.0
   */
  static PoReadRecordsBuilder prepareReadRecordFile(PoClass poClass, byte sfi, int recordNumber) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoPoUtils.SFI_MIN, CalypsoPoUtils.SFI_MAX, "sfi")
        .isInRange(
            recordNumber, CalypsoPoUtils.NB_REC_MIN, CalypsoPoUtils.NB_REC_MAX, "recordNumber");

    return new PoReadRecordsBuilder(
        poClass, sfi, recordNumber, PoReadRecordsBuilder.ReadMode.ONE_RECORD, 0);
  }

  /**
   * Create a Select File command builder for the provided LID
   *
   * @param poClass the class of the PO.
   * @param lid the LID of the EF to select.
   * @return a {@link PoSelectFileBuilder} object
   * @throws IllegalArgumentException If one of the arguments is out of range.
   * @since 2.0
   */
  static PoSelectFileBuilder prepareSelectFile(PoClass poClass, byte[] lid) {
    Assert.getInstance().notNull(lid, "lid").isEqual(lid.length, 2, "lid");

    return new PoSelectFileBuilder(poClass, lid);
  }

  /**
   * Create a Select File command builder for the provided select control
   *
   * @param poClass the class of the PO.
   * @param selectControl provides the navigation case: FIRST, NEXT or CURRENT.
   * @return a {@link PoSelectFileBuilder} object
   * @since 2.0
   */
  static PoSelectFileBuilder prepareSelectFile(PoClass poClass, SelectFileControl selectControl) {
    return new PoSelectFileBuilder(poClass, selectControl);
  }

  /**
   * (package-private)<br>
   * Gets the challenge received from the PO
   *
   * @return an array of bytes containing the challenge bytes (variable length according to the
   *     revision of the PO). May be null if the challenge is not available.
   */
  static byte[] getPoChallenge() {
    return poChallenge;
  }

  /**
   * (package-private)<br>
   * Gets the SV KVC from the PO
   *
   * @return the SV KVC byte.
   */
  static byte getSvKvc() {
    return svKvc;
  }

  /**
   * (package-private)<br>
   * Gets the SV Get command header
   *
   * @return a byte array containing the SV Get command header.
   */
  static byte[] getSvGetHeader() {
    return svGetHeader;
  }

  /**
   * (package-private)<br>
   * Gets the SV Get command response data
   *
   * @return a byte array containing the SV Get command response data.
   */
  static byte[] getSvGetData() {
    return svGetData;
  }

  /**
   * (package-private)<br>
   * Gets the last SV Operation signature (SV Reload, Debit or Undebit)
   *
   * @return a byte array containing the SV Operation signature or null if not available.
   */
  static byte[] getSvOperationSignature() {
    return svOperationSignature;
  }
}
