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

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.calypsonet.terminal.calypso.GetDataTag;
import org.calypsonet.terminal.calypso.SelectFileControl;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.card.DirectoryHeader;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.calypso.card.FileHeader;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.Assert;

/**
 * (package-private)<br>
 * Utility class used to check Calypso specific data.
 *
 * <p>Helps the preparation and the analysis of Calypso Card commands.
 *
 * @since 2.0
 */
final class CalypsoCardUtilAdapter {
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
   * The card challenge value is stored in {@link CalypsoCardUtilAdapter} and made available through
   * a dedicated getters for later use
   *
   * @param cardGetChallengeBuilder the Get Challenge command builder.
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static CardGetChallengeRespPars updateCalypsoCardGetChallenge(
      CardGetChallengeBuilder cardGetChallengeBuilder, ApduResponseApi apduResponse)
      throws CardCommandException {
    CardGetChallengeRespPars cardGetChallengeRespPars =
        cardGetChallengeBuilder.createResponseParser(apduResponse);

    cardGetChallengeRespPars.checkStatus();

    poChallenge = apduResponse.getDataOut();

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
        cardSvGetParser.getBalance(),
        cardSvGetParser.getTransactionNumber(),
        cardSvGetParser.getLoadLog(),
        cardSvGetParser.getDebitLog());

    svKvc = cardSvGetParser.getCurrentKVC();
    svGetHeader = cardSvGetParser.getSvGetCommandHeader();
    svGetData = cardSvGetParser.getApduResponse().getApdu();

    return cardSvGetParser;
  }

  /**
   * Checks the response to a SV Operation command (reload, debit or undebit) response received from
   * the card<br>
   * Keep the card SV signature if any (command executed outside a secure session).
   *
   * @param svOperationCmdBuild the SV Operation command builder (CardSvReloadBuilder,
   *     CardSvDebitBuilder or CardSvUndebitBuilder)
   * @param apduResponse the response received.
   * @throws CardCommandException if a response from the card was unexpected
   */
  private static AbstractCardResponseParser updateCalypsoCardSvOperation(
      AbstractCardCommandBuilder<? extends AbstractCardResponseParser> svOperationCmdBuild,
      ApduResponseApi apduResponse)
      throws CardCommandException {
    AbstractCardResponseParser svOperationRespPars =
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
   * @since 2.0
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
            (CardGetChallengeBuilder) commandBuilder, apduResponse);
      case VERIFY_PIN:
        return updateCalypsoVerifyPin(
            calypsoCard, (CardVerifyPinBuilder) commandBuilder, apduResponse);
      case SV_GET:
        return updateCalypsoCardSvGet(calypsoCard, (CardSvGetBuilder) commandBuilder, apduResponse);
      case SV_RELOAD:
      case SV_DEBIT:
      case SV_UNDEBIT:
        return updateCalypsoCardSvOperation(commandBuilder, apduResponse);
      case INVALIDATE:
      case REHABILITATE:
        return updateCalypsoInvalidateRehabilitate(commandBuilder, apduResponse);
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
   * @since 2.0
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

  /**
   * Create a Read Records command builder for the provided arguments
   *
   * @param calypsoCardClass the class of the card.
   * @param sfi the SFI of the EF to read.
   * @param recordNumber the record number to read.
   * @return A {@link CardReadRecordsBuilder} object
   * @throws IllegalArgumentException If one of the arguments is out of range.
   * @since 2.0
   */
  static CardReadRecordsBuilder prepareReadRecordFile(
      CalypsoCardClass calypsoCardClass, byte sfi, int recordNumber) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardUtilAdapter.SFI_MIN, CalypsoCardUtilAdapter.SFI_MAX, "sfi")
        .isInRange(
            recordNumber,
            CalypsoCardUtilAdapter.NB_REC_MIN,
            CalypsoCardUtilAdapter.NB_REC_MAX,
            "recordNumber");

    return new CardReadRecordsBuilder(
        calypsoCardClass, sfi, recordNumber, CardReadRecordsBuilder.ReadMode.ONE_RECORD, 0);
  }

  /**
   * Create a Select File command builder for the provided LID
   *
   * @param calypsoCardClass the class of the card.
   * @param lid the LID of the EF to select.
   * @return A {@link CardSelectFileBuilder} object
   * @throws IllegalArgumentException If one of the arguments is out of range.
   * @since 2.0
   */
  static CardSelectFileBuilder prepareSelectFile(CalypsoCardClass calypsoCardClass, byte[] lid) {
    Assert.getInstance().notNull(lid, "lid").isEqual(lid.length, 2, "lid");

    return new CardSelectFileBuilder(calypsoCardClass, lid);
  }

  /**
   * Create a Select File command builder for the provided select control
   *
   * @param calypsoCardClass the class of the card.
   * @param selectControl provides the navigation case: FIRST, NEXT or CURRENT.
   * @return A {@link CardSelectFileBuilder} object
   * @since 2.0
   */
  static CardSelectFileBuilder prepareSelectFile(
      CalypsoCardClass calypsoCardClass, SelectFileControl selectControl) {
    return new CardSelectFileBuilder(calypsoCardClass, selectControl);
  }

  /**
   * Create a Get Data command builder for the tag {@link GetDataTag#FCI_FOR_CURRENT_DF}.
   *
   * @param calypsoCardClass The class of the card.
   * @return A {@link CardGetDataFciBuilder} object
   * @since 2.0
   */
  static CardGetDataFciBuilder prepareGetDataFci(CalypsoCardClass calypsoCardClass) {

    return new CardGetDataFciBuilder(calypsoCardClass);
  }

  /**
   * Create a Get Data command builder for the tag {@link GetDataTag#FCP_FOR_CURRENT_FILE}.
   *
   * @param calypsoCardClass The class of the card.
   * @return A {@link CardGetDataFciBuilder} object
   * @since 2.0
   */
  static CardGetDataFcpBuilder prepareGetDataFcp(CalypsoCardClass calypsoCardClass) {

    return new CardGetDataFcpBuilder(calypsoCardClass);
  }

  /**
   * (package-private)<br>
   * Gets the challenge received from the card
   *
   * @return An array of bytes containing the challenge bytes (variable length according to the
   *     revision of the card). May be null if the challenge is not available.
   * @since 2.0
   */
  static byte[] getCardChallenge() {
    return poChallenge;
  }

  /**
   * (package-private)<br>
   * Gets the SV KVC from the card
   *
   * @return The SV KVC byte.
   * @since 2.0
   */
  static byte getSvKvc() {
    return svKvc;
  }

  /**
   * (package-private)<br>
   * Gets the SV Get command header
   *
   * @return A byte array containing the SV Get command header.
   * @throws IllegalStateException If the requested data has not been set.
   * @since 2.0
   */
  static byte[] getSvGetHeader() {
    if (svGetHeader == null) {
      throw new IllegalStateException("SV Get Header not available.");
    }
    return svGetHeader;
  }

  /**
   * (package-private)<br>
   * Gets the SV Get command response data
   *
   * @return A byte array containing the SV Get command response data.
   * @throws IllegalStateException If the requested data has not been set.
   * @since 2.0
   */
  static byte[] getSvGetData() {
    if (svGetData == null) {
      throw new IllegalStateException("SV Get Data not available.");
    }
    return svGetData;
  }

  /**
   * (package-private)<br>
   * Gets the last SV Operation signature (SV Reload, Debit or Undebit)
   *
   * @return A byte array containing the SV Operation signature or null if not available.
   * @since 2.0
   */
  static byte[] getSvOperationSignature() {
    return svOperationSignature;
  }
}
