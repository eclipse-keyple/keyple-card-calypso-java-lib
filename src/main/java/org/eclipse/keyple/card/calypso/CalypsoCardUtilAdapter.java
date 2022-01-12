/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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

import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.*;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.card.DirectoryHeader;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.calypso.card.FileHeader;
import org.calypsonet.terminal.card.ApduResponseApi;

/**
 * (package-private)<br>
 * Helper class used to update the {@link org.calypsonet.terminal.calypso.card.CalypsoCard} with the
 * responses received from the card.
 *
 * @since 2.0.0
 */
final class CalypsoCardUtilAdapter {

  /** Private constructor */
  private CalypsoCardUtilAdapter() {}

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to an Open Secure Session
   * command received from the card <br>
   * The ratification status and the data read at the time of the session opening are added to the
   * CalypsoCard.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardOpenSession the command.
   * @param apduResponse the response received.
   */
  private static void updateCalypsoCardOpenSession(
      CalypsoCardAdapter calypsoCard,
      CmdCardOpenSession cmdCardOpenSession,
      ApduResponseApi apduResponse) {

    cmdCardOpenSession.setApduResponse(apduResponse);
    // CL-CSS-INFORAT.1
    calypsoCard.setDfRatified(cmdCardOpenSession.wasRatified());

    byte[] recordDataRead = cmdCardOpenSession.getRecordDataRead();

    if (recordDataRead.length > 0) {
      calypsoCard.setContent(
          (byte) cmdCardOpenSession.getSfi(), cmdCardOpenSession.getRecordNumber(), recordDataRead);
    }
  }

  /**
   * Checks the response to a Close Session command
   *
   * @param cmdCardCloseSession the command.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoCardCloseSession(
      CmdCardCloseSession cmdCardCloseSession, ApduResponseApi apduResponse)
      throws CardCommandException {
    cmdCardCloseSession.setApduResponse(apduResponse).checkStatus();
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a Read Records command
   * received from the card <br>
   * The records read are added to the {@link CalypsoCardAdapter} file structure
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardReadRecords the command.
   * @param apduResponse the response received.
   * @param isSessionOpen true when a secure session is open.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoCardReadRecords(
      CalypsoCardAdapter calypsoCard,
      CmdCardReadRecords cmdCardReadRecords,
      ApduResponseApi apduResponse,
      boolean isSessionOpen)
      throws CardCommandException {

    if (isSessionOpen) {
      cmdCardReadRecords.setApduResponse(apduResponse).checkStatus();
    } else {
      try {
        cmdCardReadRecords.setApduResponse(apduResponse).checkStatus();
      } catch (CardDataAccessException e) {
        // best effort mode, do not throw exception for "file not found" and "record not found"
        // errors.
        if (apduResponse.getStatusWord() != 0x6A82 && apduResponse.getStatusWord() != 0x6A83) {
          throw e;
        }
      }
    }

    // iterate over read records to fill the CalypsoCard
    for (Map.Entry<Integer, byte[]> entry : cmdCardReadRecords.getRecords().entrySet()) {
      calypsoCard.setContent((byte) cmdCardReadRecords.getSfi(), entry.getKey(), entry.getValue());
    }
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a Select File command
   * received from the card <br>
   * Depending on the content of the response, either a {@link FileHeader} is added or the {@link
   * DirectoryHeader} is updated
   *
   * @param calypsoCard The {@link CalypsoCardAdapter} object to update.
   * @param command The command.
   * @param apduResponse The response received.
   * @throws CardCommandException If a response from the card was unexpected.
   */
  private static void updateCalypsoCardWithFcp(
      CalypsoCardAdapter calypsoCard, AbstractCardCommand command, ApduResponseApi apduResponse)
      throws CardCommandException {

    command.setApduResponse(apduResponse).checkStatus();

    byte[] proprietaryInformation;
    if (command.getCommandRef() == CalypsoCardCommand.SELECT_FILE) {
      proprietaryInformation = ((CmdCardSelectFile) command).getProprietaryInformation();
    } else {
      proprietaryInformation = ((CmdCardGetDataFcp) command).getProprietaryInformation();
    }
    byte sfi = proprietaryInformation[SEL_SFI_OFFSET];
    byte fileType = proprietaryInformation[SEL_TYPE_OFFSET];
    switch (fileType) {
      case FILE_TYPE_MF:
      case FILE_TYPE_DF:
        DirectoryHeader directoryHeader = createDirectoryHeader(proprietaryInformation);
        calypsoCard.setDirectoryHeader(directoryHeader);
        break;
      case FILE_TYPE_EF:
        FileHeader fileHeader = createFileHeader(proprietaryInformation);
        calypsoCard.setFileHeader(sfi, fileHeader);
        break;
      default:
        throw new IllegalStateException(String.format("Unknown file type: 0x%02X", fileType));
    }
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a "Get Data" command for
   * {@link org.calypsonet.terminal.calypso.GetDataTag#EF_LIST} tag received from the card.
   *
   * <p>Non-existing file headers will be created for each received descriptor. Existing file
   * headers will remain unchanged.
   *
   * @param calypsoCard The {@link CalypsoCardAdapter} object to update.
   * @param command The command.
   * @param apduResponse The response received.
   * @throws CardCommandException If a response from the card was unexpected.
   */
  private static void updateCalypsoCardWithEfList(
      CalypsoCardAdapter calypsoCard, CmdCardGetDataEfList command, ApduResponseApi apduResponse)
      throws CardCommandException {

    command.setApduResponse(apduResponse).checkStatus();

    Map<Byte, FileHeader> sfiToFileHeaderMap = command.getEfHeaders();

    for (Map.Entry<Byte, FileHeader> entry : sfiToFileHeaderMap.entrySet()) {
      if (calypsoCard.getFileBySfi(entry.getKey()) == null
          || calypsoCard.getFileBySfi(entry.getKey()).getHeader() == null) {
        calypsoCard.setFileHeader(entry.getKey(), entry.getValue());
      }
    }
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a "Get Data" command for
   * {@link org.calypsonet.terminal.calypso.GetDataTag#TRACEABILITY_INFORMATION} tag received from
   * the card.
   *
   * @param calypsoCard The {@link CalypsoCardAdapter} object to update.
   * @param command The command.
   * @param apduResponse The response received.
   * @throws CardCommandException if a response from the card was unexpected.
   */
  private static void updateCalypsoCardWithTraceabilityInformation(
      CalypsoCardAdapter calypsoCard,
      CmdCardGetDataTraceabilityInformation command,
      ApduResponseApi apduResponse)
      throws CardCommandException {

    command.setApduResponse(apduResponse).checkStatus();

    calypsoCard.setTraceabilityInformation(apduResponse.getDataOut());
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to an "Update Record" command
   * sent and received from the card.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardUpdateRecord the command.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoCardUpdateRecord(
      CalypsoCardAdapter calypsoCard,
      CmdCardUpdateRecord cmdCardUpdateRecord,
      ApduResponseApi apduResponse)
      throws CardCommandException {

    cmdCardUpdateRecord.setApduResponse(apduResponse).checkStatus();

    calypsoCard.setContent(
        (byte) cmdCardUpdateRecord.getSfi(),
        cmdCardUpdateRecord.getRecordNumber(),
        cmdCardUpdateRecord.getData());
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a "Write Record" command
   * sent and received from the card.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardWriteRecord the command.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoCardWriteRecord(
      CalypsoCardAdapter calypsoCard,
      CmdCardWriteRecord cmdCardWriteRecord,
      ApduResponseApi apduResponse)
      throws CardCommandException {

    cmdCardWriteRecord.setApduResponse(apduResponse).checkStatus();

    calypsoCard.fillContent(
        (byte) cmdCardWriteRecord.getSfi(),
        cmdCardWriteRecord.getRecordNumber(),
        cmdCardWriteRecord.getData(),
        0);
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to an "Update Binary" command
   * sent and received from the card.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardUpdateBinary the command.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoCardUpdateBinary(
      CalypsoCardAdapter calypsoCard,
      CmdCardUpdateOrWriteBinary cmdCardUpdateBinary,
      ApduResponseApi apduResponse)
      throws CardCommandException {

    cmdCardUpdateBinary.setApduResponse(apduResponse).checkStatus();

    calypsoCard.setContent(
        cmdCardUpdateBinary.getSfi(),
        1,
        cmdCardUpdateBinary.getData(),
        cmdCardUpdateBinary.getOffset());
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a "Write Binary" command
   * sent and received from the card.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardWriteBinary the command.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoCardWriteBinary(
      CalypsoCardAdapter calypsoCard,
      CmdCardUpdateOrWriteBinary cmdCardWriteBinary,
      ApduResponseApi apduResponse)
      throws CardCommandException {

    cmdCardWriteBinary.setApduResponse(apduResponse).checkStatus();

    calypsoCard.fillContent(
        cmdCardWriteBinary.getSfi(),
        1,
        cmdCardWriteBinary.getData(),
        cmdCardWriteBinary.getOffset());
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a Read Records command
   * received from the card <br>
   * The records read are added to the {@link CalypsoCardAdapter} file structure
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardAppendRecord the command.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoCardAppendRecord(
      CalypsoCardAdapter calypsoCard,
      CmdCardAppendRecord cmdCardAppendRecord,
      ApduResponseApi apduResponse)
      throws CardCommandException {

    cmdCardAppendRecord.setApduResponse(apduResponse).checkStatus();

    calypsoCard.addCyclicContent(
        (byte) cmdCardAppendRecord.getSfi(), cmdCardAppendRecord.getData());
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a Decrease command received
   * from the card <br>
   * The counter value is updated in the {@link CalypsoCardAdapter} file structure
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardDecrease the command.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoCardDecrease(
      CalypsoCardAdapter calypsoCard, CmdCardDecrease cmdCardDecrease, ApduResponseApi apduResponse)
      throws CardCommandException {

    cmdCardDecrease.setApduResponse(apduResponse).checkStatus();

    calypsoCard.setContent(
        (byte) cmdCardDecrease.getSfi(),
        1,
        apduResponse.getDataOut(),
        3 * (cmdCardDecrease.getCounterNumber() - 1));
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to an Increase command received
   * from the card <br>
   * The counter value is updated in the {@link CalypsoCardAdapter} file structure
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardIncrease the command.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoCardIncrease(
      CalypsoCardAdapter calypsoCard, CmdCardIncrease cmdCardIncrease, ApduResponseApi apduResponse)
      throws CardCommandException {

    cmdCardIncrease.setApduResponse(apduResponse).checkStatus();

    calypsoCard.setContent(
        (byte) cmdCardIncrease.getSfi(),
        1,
        apduResponse.getDataOut(),
        3 * (cmdCardIncrease.getCounterNumber() - 1));
  }

  /**
   * Parses the response to a Get Challenge command received from the card <br>
   * The card challenge value is stored in {@link CalypsoCardAdapter}.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardGetChallenge the command.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoCardGetChallenge(
      CalypsoCardAdapter calypsoCard,
      CmdCardGetChallenge cmdCardGetChallenge,
      ApduResponseApi apduResponse)
      throws CardCommandException {

    cmdCardGetChallenge.setApduResponse(apduResponse).checkStatus();
    calypsoCard.setCardChallenge(cmdCardGetChallenge.getCardChallenge());
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a "Verify Pin" command
   * received from the card <br>
   * The PIN attempt counter value is stored in the {@link CalypsoCardAdapter}<br>
   * CardPinException are filtered when the initial command targets the reading of the attempt
   * counter.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardVerifyPin the command.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoVerifyPin(
      CalypsoCardAdapter calypsoCard,
      CmdCardVerifyPin cmdCardVerifyPin,
      ApduResponseApi apduResponse)
      throws CardCommandException {

    cmdCardVerifyPin.setApduResponse(apduResponse);
    calypsoCard.setPinAttemptRemaining(cmdCardVerifyPin.getRemainingAttemptCounter());

    try {
      cmdCardVerifyPin.checkStatus();
    } catch (CardPinException ex) {
      // forward the exception if the operation do not target the reading of the attempt
      // counter.
      // catch it silently otherwise
      if (!cmdCardVerifyPin.isReadCounterOnly()) {
        throw ex;
      }
    }
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a "Change Pin" command
   * received from the card
   *
   * @param cmdCardChangePin the command.
   * @param apduResponse the response received.
   */
  private static void updateCalypsoChangePin(
      CmdCardChangePin cmdCardChangePin, ApduResponseApi apduResponse) throws CardCommandException {
    cmdCardChangePin.setApduResponse(apduResponse).checkStatus();
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to an SV Get command received
   * from the card <br>
   * The SV Data values (KVC, command header, response data) are stored in {@link
   * CalypsoCardUtilAdapter} and made available through a dedicated getters for later use<br>
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardSvGet the command.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoCardSvGet(
      CalypsoCardAdapter calypsoCard, CmdCardSvGet cmdCardSvGet, ApduResponseApi apduResponse)
      throws CardCommandException {

    cmdCardSvGet.setApduResponse(apduResponse).checkStatus();

    calypsoCard.setSvData(
        cmdCardSvGet.getCurrentKVC(),
        cmdCardSvGet.getSvGetCommandHeader(),
        cmdCardSvGet.getApduResponse().getApdu(),
        cmdCardSvGet.getBalance(),
        cmdCardSvGet.getTransactionNumber(),
        cmdCardSvGet.getLoadLog(),
        cmdCardSvGet.getDebitLog());
  }

  /**
   * Checks the response to a SV Operation command (reload, debit or undebit) response received from
   * the card<br>
   * Stores the card SV signature if any (command executed outside a secure session) in the {@link
   * CalypsoCardAdapter}.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cmdCardSvOperation the SV Operation command (CmdCardSvReload, CmdCardSvDebit or
   *     CmdCardSvUndebit)
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoCardSvOperation(
      CalypsoCardAdapter calypsoCard,
      AbstractCardCommand cmdCardSvOperation,
      ApduResponseApi apduResponse)
      throws CardCommandException {

    cmdCardSvOperation.setApduResponse(apduResponse).checkStatus();
    calypsoCard.setSvOperationSignature(cmdCardSvOperation.getApduResponse().getDataOut());
  }

  /**
   * Checks the response to Invalidate/Rehabilitate commands
   *
   * @param cmdCardInvalidateRehabilitate the Invalidate or Rehabilitate command.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static void updateCalypsoInvalidateRehabilitate(
      AbstractCardCommand cmdCardInvalidateRehabilitate, ApduResponseApi apduResponse)
      throws CardCommandException {
    cmdCardInvalidateRehabilitate.setApduResponse(apduResponse).checkStatus();
  }

  /**
   * Parses the proprietaryInformation field of a file identified as an DF and create a {@link
   * DirectoryHeader}
   *
   * @param proprietaryInformation from the response to a Select File command.
   * @return A {@link DirectoryHeader} object
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
        .kvc(WriteAccessLevel.PERSONALIZATION, proprietaryInformation[SEL_KVCS_OFFSET])
        .kvc(WriteAccessLevel.LOAD, proprietaryInformation[SEL_KVCS_OFFSET + 1])
        .kvc(WriteAccessLevel.DEBIT, proprietaryInformation[SEL_KVCS_OFFSET + 2])
        .kif(WriteAccessLevel.PERSONALIZATION, proprietaryInformation[SEL_KIFS_OFFSET])
        .kif(WriteAccessLevel.LOAD, proprietaryInformation[SEL_KIFS_OFFSET + 1])
        .kif(WriteAccessLevel.DEBIT, proprietaryInformation[SEL_KIFS_OFFSET + 2])
        .build();
  }

  /**
   * Converts the EF type value from the card into a {@link ElementaryFile.Type} enum
   *
   * @param efType the value returned by the card.
   * @return The corresponding {@link ElementaryFile.Type}
   */
  private static ElementaryFile.Type getEfTypeFromCardValue(byte efType) {
    ElementaryFile.Type fileType;
    switch (efType) {
      case EF_TYPE_BINARY:
        fileType = ElementaryFile.Type.BINARY;
        break;
      case EF_TYPE_LINEAR:
        fileType = ElementaryFile.Type.LINEAR;
        break;
      case EF_TYPE_CYCLIC:
        fileType = ElementaryFile.Type.CYCLIC;
        break;
      case EF_TYPE_SIMULATED_COUNTERS:
        fileType = ElementaryFile.Type.SIMULATED_COUNTERS;
        break;
      case EF_TYPE_COUNTERS:
        fileType = ElementaryFile.Type.COUNTERS;
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
   * @return A {@link FileHeader} object
   */
  private static FileHeader createFileHeader(byte[] proprietaryInformation) {

    ElementaryFile.Type fileType =
        getEfTypeFromCardValue(proprietaryInformation[SEL_EF_TYPE_OFFSET]);

    int recordSize;
    int recordsNumber;
    if (fileType == ElementaryFile.Type.BINARY) {
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
   * Fills the CalypsoCard with the card's response to a single command
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to fill with the provided response
   *     from the card.
   * @param command the command that get the response.
   * @param apduResponse the APDU response returned by the card to the command.
   * @param isSessionOpen true when a secure session is open.
   * @throws CardCommandException if a response from the card was unexpected
   * @since 2.0.0
   */
  static void updateCalypsoCard(
      CalypsoCardAdapter calypsoCard,
      AbstractCardCommand command,
      ApduResponseApi apduResponse,
      boolean isSessionOpen)
      throws CardCommandException {

    switch (command.getCommandRef()) {
      case READ_RECORDS:
        updateCalypsoCardReadRecords(
            calypsoCard, (CmdCardReadRecords) command, apduResponse, isSessionOpen);
        break;
      case GET_DATA:
        if (command instanceof CmdCardGetDataFci) {
          calypsoCard.initializeWithFci(apduResponse);
        } else if (command instanceof CmdCardGetDataFcp) {
          updateCalypsoCardWithFcp(calypsoCard, command, apduResponse);
        } else if (command instanceof CmdCardGetDataEfList) {
          updateCalypsoCardWithEfList(calypsoCard, (CmdCardGetDataEfList) command, apduResponse);
        } else if (command instanceof CmdCardGetDataTraceabilityInformation) {
          updateCalypsoCardWithTraceabilityInformation(
              calypsoCard, (CmdCardGetDataTraceabilityInformation) command, apduResponse);
        } else {
          throw new IllegalStateException("Unknown GET DATA command reference.");
        }
        break;
      case SELECT_FILE:
        updateCalypsoCardWithFcp(calypsoCard, command, apduResponse);
        break;
      case UPDATE_RECORD:
        updateCalypsoCardUpdateRecord(calypsoCard, (CmdCardUpdateRecord) command, apduResponse);
        break;
      case WRITE_RECORD:
        updateCalypsoCardWriteRecord(calypsoCard, (CmdCardWriteRecord) command, apduResponse);
        break;
      case UPDATE_BINARY:
        updateCalypsoCardUpdateBinary(
            calypsoCard, (CmdCardUpdateOrWriteBinary) command, apduResponse);
        break;
      case WRITE_BINARY:
        updateCalypsoCardWriteBinary(
            calypsoCard, (CmdCardUpdateOrWriteBinary) command, apduResponse);
        break;
      case APPEND_RECORD:
        updateCalypsoCardAppendRecord(calypsoCard, (CmdCardAppendRecord) command, apduResponse);
        break;
      case DECREASE:
        updateCalypsoCardDecrease(calypsoCard, (CmdCardDecrease) command, apduResponse);
        break;
      case INCREASE:
        updateCalypsoCardIncrease(calypsoCard, (CmdCardIncrease) command, apduResponse);
        break;
      case OPEN_SESSION:
        updateCalypsoCardOpenSession(calypsoCard, (CmdCardOpenSession) command, apduResponse);
        break;
      case CLOSE_SESSION:
        updateCalypsoCardCloseSession((CmdCardCloseSession) command, apduResponse);
        break;
      case GET_CHALLENGE:
        updateCalypsoCardGetChallenge(calypsoCard, (CmdCardGetChallenge) command, apduResponse);
        break;
      case VERIFY_PIN:
        updateCalypsoVerifyPin(calypsoCard, (CmdCardVerifyPin) command, apduResponse);
        break;
      case SV_GET:
        updateCalypsoCardSvGet(calypsoCard, (CmdCardSvGet) command, apduResponse);
        break;
      case SV_RELOAD:
      case SV_DEBIT:
      case SV_UNDEBIT:
        updateCalypsoCardSvOperation(calypsoCard, command, apduResponse);
        break;
      case INVALIDATE:
      case REHABILITATE:
        updateCalypsoInvalidateRehabilitate(command, apduResponse);
        break;
      case CHANGE_PIN:
        updateCalypsoChangePin((CmdCardChangePin) command, apduResponse);
        break;
      case CHANGE_KEY:
        throw new IllegalStateException("Shouldn't happen for now!");
      default:
        throw new IllegalStateException("Unknown command reference.");
    }
  }

  /**
   * (package-private)<br>
   * Fills the CalypsoCard with the card's responses to a list of commands
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to fill with the provided response
   *     from the card
   * @param commands the list of commands that get the responses.
   * @param apduResponses the APDU responses returned by the card to all commands.
   * @param isSessionOpen true when a secure session is open.
   * @throws CardCommandException if a response from the card was unexpected
   * @since 2.0.0
   */
  static void updateCalypsoCard(
      CalypsoCardAdapter calypsoCard,
      List<AbstractCardCommand> commands,
      List<ApduResponseApi> apduResponses,
      boolean isSessionOpen)
      throws CardCommandException {

    Iterator<ApduResponseApi> responseIterator = apduResponses.iterator();

    if (commands != null && !commands.isEmpty()) {
      for (AbstractCardCommand command : commands) {
        ApduResponseApi apduResponse = responseIterator.next();
        updateCalypsoCard(calypsoCard, command, apduResponse, isSessionOpen);
      }
    }
  }
}
