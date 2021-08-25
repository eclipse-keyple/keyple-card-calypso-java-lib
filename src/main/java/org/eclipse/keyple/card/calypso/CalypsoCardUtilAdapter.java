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
   * Updates the {@link CalypsoCardAdapter} object with the response to a Open Secure Session
   * command received from the card <br>
   * The ratification status and the data read at the time of the session opening are added to the
   * CalypsoCard.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param openSessionCmdBuild the Open Secure Session command builder.
   * @param apduResponse the response received.
   * @return The created response parser
   */
  private static AbstractCardOpenSessionParser updateCalypsoCardOpenSession(
      CalypsoCardAdapter calypsoCard,
      AbstractCardOpenSessionBuilder<AbstractCardOpenSessionParser> openSessionCmdBuild,
      ApduResponseApi apduResponse) {
    // create parser
    AbstractCardOpenSessionParser openSessionRespPars =
        openSessionCmdBuild.createResponseParser(apduResponse);

    calypsoCard.setDfRatified(openSessionRespPars.wasRatified());

    byte[] recordDataRead = openSessionRespPars.getRecordDataRead();

    if (recordDataRead.length > 0) {
      calypsoCard.setContent(
          (byte) openSessionCmdBuild.getSfi(),
          openSessionCmdBuild.getRecordNumber(),
          recordDataRead);
    }

    return openSessionRespPars;
  }

  /**
   * Checks the response to a Close Session command
   *
   * @param cardCloseSessionBuilder the Close Session command builder.
   * @param apduResponse the response received.
   * @return The created response parser
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static CardCloseSessionParser updateCalypsoCardCloseSession(
      CardCloseSessionBuilder cardCloseSessionBuilder, ApduResponseApi apduResponse)
      throws CardCommandException {
    CardCloseSessionParser cardCloseSessionParser =
        cardCloseSessionBuilder.createResponseParser(apduResponse);

    cardCloseSessionParser.checkStatus();

    return cardCloseSessionParser;
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a Read Records command
   * received from the card <br>
   * The records read are added to the {@link CalypsoCardAdapter} file structure
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cardReadRecordsBuilder the Read Records command builder.
   * @param apduResponse the response received.
   * @return The created response parser
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static CardReadRecordsParser updateCalypsoCardReadRecords(
      CalypsoCardAdapter calypsoCard,
      CardReadRecordsBuilder cardReadRecordsBuilder,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    // create parser
    CardReadRecordsParser cardReadRecordsParser =
        cardReadRecordsBuilder.createResponseParser(apduResponse);

    cardReadRecordsParser.checkStatus();

    // iterate over read records to fill the CalypsoCard
    for (Map.Entry<Integer, byte[]> entry : cardReadRecordsParser.getRecords().entrySet()) {
      calypsoCard.setContent(
          (byte) cardReadRecordsBuilder.getSfi(), entry.getKey(), entry.getValue());
    }
    return cardReadRecordsParser;
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a Select File command
   * received from the card <br>
   * Depending on the content of the response, either a {@link FileHeader} is added or the {@link
   * DirectoryHeader} is updated
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static CardSelectFileParser updateCalypsoCardWithFcp(
      CalypsoCardAdapter calypsoCard, ApduResponseApi apduResponse) throws CardCommandException {

    CardSelectFileParser cardSelectFileParser = new CardSelectFileParser(apduResponse, null);

    cardSelectFileParser.checkStatus();

    byte[] proprietaryInformation = cardSelectFileParser.getProprietaryInformation();
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
    return cardSelectFileParser;
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a Update Record command sent
   * and received from the card <br>
   * The records read are added to the {@link CalypsoCardAdapter} file structure
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cardUpdateRecordBuilder the Update Record command builder.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static CardUpdateRecordParser updateCalypsoCardUpdateRecord(
      CalypsoCardAdapter calypsoCard,
      CardUpdateRecordBuilder cardUpdateRecordBuilder,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    CardUpdateRecordParser cardUpdateRecordParser =
        cardUpdateRecordBuilder.createResponseParser(apduResponse);

    cardUpdateRecordParser.checkStatus();

    calypsoCard.setContent(
        (byte) cardUpdateRecordBuilder.getSfi(),
        cardUpdateRecordBuilder.getRecordNumber(),
        cardUpdateRecordBuilder.getData());

    return cardUpdateRecordParser;
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a Write Record command sent
   * and received from the card <br>
   * The records read are added to the {@link CalypsoCardAdapter} file structure using the dedicated
   * {@link CalypsoCardAdapter#fillContent } method.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cardWriteRecordBuilder the Write Record command builder.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static CardWriteRecordParser updateCalypsoCardWriteRecord(
      CalypsoCardAdapter calypsoCard,
      CardWriteRecordBuilder cardWriteRecordBuilder,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    CardWriteRecordParser cardWriteRecordParser =
        cardWriteRecordBuilder.createResponseParser(apduResponse);

    cardWriteRecordParser.checkStatus();

    calypsoCard.fillContent(
        (byte) cardWriteRecordBuilder.getSfi(),
        cardWriteRecordBuilder.getRecordNumber(),
        cardWriteRecordBuilder.getData());

    return cardWriteRecordParser;
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a Read Records command
   * received from the card <br>
   * The records read are added to the {@link CalypsoCardAdapter} file structure
   *
   * @param cardAppendRecordBuilder the Append Records command builder.
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static CardAppendRecordParser updateCalypsoCardAppendRecord(
      CalypsoCardAdapter calypsoCard,
      CardAppendRecordBuilder cardAppendRecordBuilder,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    CardAppendRecordParser cardAppendRecordParser =
        cardAppendRecordBuilder.createResponseParser(apduResponse);

    cardAppendRecordParser.checkStatus();

    calypsoCard.addCyclicContent(
        (byte) cardAppendRecordBuilder.getSfi(), cardAppendRecordBuilder.getData());

    return cardAppendRecordParser;
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to a Decrease command received
   * from the card <br>
   * The counter value is updated in the {@link CalypsoCardAdapter} file structure
   *
   * @param cardDecreaseBuilder the Decrease command builder.
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static CardDecreaseParser updateCalypsoCardDecrease(
      CalypsoCardAdapter calypsoCard,
      CardDecreaseBuilder cardDecreaseBuilder,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    CardDecreaseParser cardDecreaseParser = cardDecreaseBuilder.createResponseParser(apduResponse);

    cardDecreaseParser.checkStatus();

    calypsoCard.setContent(
        (byte) cardDecreaseBuilder.getSfi(),
        1,
        apduResponse.getDataOut(),
        3 * (cardDecreaseBuilder.getCounterNumber() - 1));

    return cardDecreaseParser;
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to an Increase command received
   * from the card <br>
   * The counter value is updated in the {@link CalypsoCardAdapter} file structure
   *
   * @param cardIncreaseBuilder the Increase command builder.
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static CardIncreaseParser updateCalypsoCardIncrease(
      CalypsoCardAdapter calypsoCard,
      CardIncreaseBuilder cardIncreaseBuilder,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    CardIncreaseParser cardIncreaseParser = cardIncreaseBuilder.createResponseParser(apduResponse);

    cardIncreaseParser.checkStatus();

    calypsoCard.setContent(
        (byte) cardIncreaseBuilder.getSfi(),
        1,
        apduResponse.getDataOut(),
        3 * (cardIncreaseBuilder.getCounterNumber() - 1));

    return cardIncreaseParser;
  }

  /**
   * Parses the response to a Get Challenge command received from the card <br>
   * The card challenge value is stored in {@link CalypsoCardAdapter}.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cardGetChallengeBuilder the Get Challenge command builder.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static CardGetChallengeRespPars updateCalypsoCardGetChallenge(
      CalypsoCardAdapter calypsoCard,
      CardGetChallengeBuilder cardGetChallengeBuilder,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    CardGetChallengeRespPars cardGetChallengeRespPars =
        cardGetChallengeBuilder.createResponseParser(apduResponse);

    cardGetChallengeRespPars.checkStatus();

    calypsoCard.setCardChallenge(apduResponse.getDataOut());

    return cardGetChallengeRespPars;
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to an Verify Pin command
   * received from the card <br>
   * The PIN attempt counter value is stored in the {@link CalypsoCardAdapter}<br>
   * CardPinException are filtered when the initial command targets the reading of the attempt
   * counter.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cardVerifyPinBuilder the Verify PIN command builder.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static CardVerifyPinParser updateCalypsoVerifyPin(
      CalypsoCardAdapter calypsoCard,
      CardVerifyPinBuilder cardVerifyPinBuilder,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    CardVerifyPinParser cardVerifyPinParser =
        cardVerifyPinBuilder.createResponseParser(apduResponse);

    calypsoCard.setPinAttemptRemaining(cardVerifyPinParser.getRemainingAttemptCounter());

    try {
      cardVerifyPinParser.checkStatus();
    } catch (CardPinException ex) {
      // forward the exception if the operation do not target the reading of the attempt
      // counter.
      // catch it silently otherwise
      if (!cardVerifyPinBuilder.isReadCounterOnly()) {
        throw ex;
      }
    }

    return cardVerifyPinParser;
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to an Change Pin command
   * received from the card
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cardChangePinBuilder the Change PIN command builder.
   * @param apduResponse the response received.
   * @return The command parser.
   */
  private static CardChangePinParser updateCalypsoChangePin(
      CalypsoCardAdapter calypsoCard,
      CardChangePinBuilder cardChangePinBuilder,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    CardChangePinParser cardChangePinParser =
        cardChangePinBuilder.createResponseParser(apduResponse);
    cardChangePinParser.checkStatus();
    return cardChangePinParser;
  }

  /**
   * Updates the {@link CalypsoCardAdapter} object with the response to an SV Get command received
   * from the card <br>
   * The SV Data values (KVC, command header, response data) are stored in {@link
   * CalypsoCardUtilAdapter} and made available through a dedicated getters for later use<br>
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param cardSvGetBuilder the SV Get command builder.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static CardSvGetParser updateCalypsoCardSvGet(
      CalypsoCardAdapter calypsoCard,
      CardSvGetBuilder cardSvGetBuilder,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    CardSvGetParser cardSvGetParser = cardSvGetBuilder.createResponseParser(apduResponse);

    cardSvGetParser.checkStatus();

    calypsoCard.setSvData(
        cardSvGetParser.getCurrentKVC(),
        cardSvGetParser.getSvGetCommandHeader(),
        cardSvGetParser.getApduResponse().getApdu(),
        cardSvGetParser.getBalance(),
        cardSvGetParser.getTransactionNumber(),
        cardSvGetParser.getLoadLog(),
        cardSvGetParser.getDebitLog());

    return cardSvGetParser;
  }

  /**
   * Checks the response to a SV Operation command (reload, debit or undebit) response received from
   * the card<br>
   * Stores the card SV signature if any (command executed outside a secure session) in the {@link
   * CalypsoCardAdapter}.
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to update.
   * @param svOperationCmdBuild the SV Operation command builder (CardSvReloadBuilder,
   *     CardSvDebitBuilder or CardSvUndebitBuilder)
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static AbstractCardResponseParser updateCalypsoCardSvOperation(
      CalypsoCardAdapter calypsoCard,
      AbstractCardCommandBuilder<? extends AbstractCardResponseParser> svOperationCmdBuild,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    AbstractCardResponseParser svOperationRespPars =
        svOperationCmdBuild.createResponseParser(apduResponse);

    svOperationRespPars.checkStatus();

    calypsoCard.setSvOperationSignature(svOperationRespPars.getApduResponse().getDataOut());

    return svOperationRespPars;
  }

  /**
   * Checks the response to Invalidate/Rehabilitate commands
   *
   * @param invalidateRehabilitateCmdBuild the Invalidate or Rehabilitate response parser.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static AbstractCardResponseParser updateCalypsoInvalidateRehabilitate(
      AbstractCardCommandBuilder<? extends AbstractCardResponseParser>
          invalidateRehabilitateCmdBuild,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    AbstractCardResponseParser invalidateRehabilitateRespPars =
        invalidateRehabilitateCmdBuild.createResponseParser(apduResponse);

    invalidateRehabilitateRespPars.checkStatus();

    return invalidateRehabilitateRespPars;
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
   * @param calypsoCard the {@link CalypsoCardAdapter} object to fill with the. provided response
   *     from the card
   * @param commandBuilder the builder of the command that get the response.
   * @param apduResponse the APDU response returned by the card to the command.
   * @return The parser associated to the command or null if not relevant.
   * @throws CardCommandException if a response from the card was unexpected
   * @since 2.0.0
   */
  static AbstractCardResponseParser updateCalypsoCard(
      CalypsoCardAdapter calypsoCard,
      AbstractCardCommandBuilder<? extends AbstractCardResponseParser> commandBuilder,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    switch (commandBuilder.getCommandRef()) {
      case READ_RECORDS:
        return updateCalypsoCardReadRecords(
            calypsoCard, (CardReadRecordsBuilder) commandBuilder, apduResponse);
      case GET_DATA:
        if (commandBuilder instanceof CardGetDataFciBuilder) {
          calypsoCard.initializeWithFci(apduResponse);
          return null;
        } else {
          return updateCalypsoCardWithFcp(calypsoCard, apduResponse);
        }
      case SELECT_FILE:
        return updateCalypsoCardWithFcp(calypsoCard, apduResponse);
      case UPDATE_RECORD:
        return updateCalypsoCardUpdateRecord(
            calypsoCard, (CardUpdateRecordBuilder) commandBuilder, apduResponse);
      case WRITE_RECORD:
        return updateCalypsoCardWriteRecord(
            calypsoCard, (CardWriteRecordBuilder) commandBuilder, apduResponse);
      case APPEND_RECORD:
        return updateCalypsoCardAppendRecord(
            calypsoCard, (CardAppendRecordBuilder) commandBuilder, apduResponse);
      case DECREASE:
        return updateCalypsoCardDecrease(
            calypsoCard, (CardDecreaseBuilder) commandBuilder, apduResponse);
      case INCREASE:
        return updateCalypsoCardIncrease(
            calypsoCard, (CardIncreaseBuilder) commandBuilder, apduResponse);
      case OPEN_SESSION_10:
      case OPEN_SESSION_24:
      case OPEN_SESSION_3X:
        return updateCalypsoCardOpenSession(
            calypsoCard,
            (AbstractCardOpenSessionBuilder<AbstractCardOpenSessionParser>) commandBuilder,
            apduResponse);
      case CLOSE_SESSION:
        return updateCalypsoCardCloseSession(
            (CardCloseSessionBuilder) commandBuilder, apduResponse);
      case GET_CHALLENGE:
        return updateCalypsoCardGetChallenge(
            calypsoCard, (CardGetChallengeBuilder) commandBuilder, apduResponse);
      case VERIFY_PIN:
        return updateCalypsoVerifyPin(
            calypsoCard, (CardVerifyPinBuilder) commandBuilder, apduResponse);
      case SV_GET:
        return updateCalypsoCardSvGet(calypsoCard, (CardSvGetBuilder) commandBuilder, apduResponse);
      case SV_RELOAD:
      case SV_DEBIT:
      case SV_UNDEBIT:
        return updateCalypsoCardSvOperation(calypsoCard, commandBuilder, apduResponse);
      case INVALIDATE:
      case REHABILITATE:
        return updateCalypsoInvalidateRehabilitate(commandBuilder, apduResponse);
      case CHANGE_PIN:
        return updateCalypsoChangePin(
            calypsoCard, (CardChangePinBuilder) commandBuilder, apduResponse);
      case CHANGE_KEY:
      case GET_DATA_TRACE:
        throw new IllegalStateException("Shouldn't happen for now!");
      default:
        throw new IllegalStateException("Unknown command reference.");
    }
  }

  /**
   * (package-private)<br>
   * Fills the CalypsoCard with the card's responses to a list of commands
   *
   * @param calypsoCard the {@link CalypsoCardAdapter} object to fill with the. provided response
   *     from the card
   * @param commandBuilders the list of builders that get the responses.
   * @param apduResponses the APDU responses returned by the card to all commands.
   * @throws CardCommandException if a response from the card was unexpected
   * @since 2.0.0
   */
  static void updateCalypsoCard(
      CalypsoCardAdapter calypsoCard,
      List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>> commandBuilders,
      List<ApduResponseApi> apduResponses)
      throws CardCommandException {
    Iterator<ApduResponseApi> responseIterator = apduResponses.iterator();

    if (commandBuilders != null && !commandBuilders.isEmpty()) {
      for (AbstractCardCommandBuilder<? extends AbstractCardResponseParser> commandBuilder :
          commandBuilders) {
        ApduResponseApi apduResponse = responseIterator.next();
        updateCalypsoCard(calypsoCard, commandBuilder, apduResponse);
      }
    }
  }
}
