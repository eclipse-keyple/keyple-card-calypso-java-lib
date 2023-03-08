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

import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.EF_TYPE_BINARY;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.EF_TYPE_COUNTERS;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.EF_TYPE_CYCLIC;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.EF_TYPE_LINEAR;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.EF_TYPE_SIMULATED_COUNTERS;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.FILE_TYPE_DF;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.FILE_TYPE_EF;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.FILE_TYPE_MF;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_AC_LENGTH;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_AC_OFFSET;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_DATA_REF_OFFSET;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_DF_STATUS_OFFSET;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_EF_TYPE_OFFSET;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_KIFS_OFFSET;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_KVCS_OFFSET;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_LID_OFFSET;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_LID_OFFSET_REV2;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_NKEY_LENGTH;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_NKEY_OFFSET;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_NUM_REC_OFFSET;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_REC_SIZE_OFFSET;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_SFI_OFFSET;
import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.SEL_TYPE_OFFSET;
import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.SelectFileControl;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.calypso.card.DirectoryHeader;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.calypso.transaction.SelectFileException;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.BerTlvUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the Select File APDU commands.
 *
 * <p>The value of the Proprietary Information tag is extracted from the Select File response and
 * made available using the corresponding getter.
 *
 * @since 2.0.1
 */
final class CmdCardSelectFile extends CardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardSelectFile.class);

  private static final CardCommandRef commandRef = CardCommandRef.SELECT_FILE;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CardIllegalParameterException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
    m.put(0x6119, new StatusProperties("Correct execution (ISO7816 T=0)."));
    STATUS_TABLE = m;
  }

  private static final int TAG_PROPRIETARY_INFORMATION = 0x85;

  /**
   * Instantiates a new CmdCardSelectFile to select the first, next or current file in the current
   * DF.
   *
   * @param calypsoCard The Calypso card.
   * @param selectFileControl the selection mode control: FIRST, NEXT or CURRENT.
   * @since 2.2.3
   * @deprecated
   */
  @Deprecated
  CmdCardSelectFile(CalypsoCardAdapter calypsoCard, SelectFileControl selectFileControl) {
    super(commandRef, 0, calypsoCard, null, null);
    buildCommand(calypsoCard.getCardClass(), selectFileControl);
  }

  /**
   * Instantiates a new CmdCardSelectFile to select the first, next or current file in the current
   * DF.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param selectFileControl the selection mode control: FIRST, NEXT or CURRENT.
   * @since 2.3.2
   */
  CmdCardSelectFile(
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      SelectFileControl selectFileControl) {
    super(commandRef, 0, null, transactionContext, commandContext);
    buildCommand(transactionContext.getCard().getCardClass(), selectFileControl);
  }

  /**
   * Instantiates a new CmdCardSelectFile to select the first, next or current file in the current
   * DF.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param selectFileControl the selection mode control: FIRST, NEXT or CURRENT.
   * @since 2.0.1
   */
  CmdCardSelectFile(CalypsoCardClass calypsoCardClass, SelectFileControl selectFileControl) {
    super(commandRef, 0, null, null, null);
    buildCommand(calypsoCardClass, selectFileControl);
  }

  /**
   * Instantiates a new CmdCardSelectFile to select the first, next or current file in the current
   * DF.
   *
   * @param calypsoCard The Calypso card.
   * @param lid The LID.
   * @since 2.2.3
   * @deprecated
   */
  @Deprecated
  CmdCardSelectFile(CalypsoCardAdapter calypsoCard, short lid) {
    super(commandRef, 0, calypsoCard, null, null);
    buildCommand(calypsoCard.getCardClass(), calypsoCard.getProductType(), lid);
  }

  /**
   * Instantiates a new CmdCardSelectFile to select the first, next or current file in the current
   * DF.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param lid The LID.
   * @since 2.3.2
   */
  CmdCardSelectFile(
      TransactionContextDto transactionContext, CommandContextDto commandContext, short lid) {
    super(commandRef, 0, null, transactionContext, commandContext);
    buildCommand(
        transactionContext.getCard().getCardClass(),
        transactionContext.getCard().getProductType(),
        lid);
  }

  /**
   * Instantiates a new CmdCardSelectFile to select the first, next or current file in the current
   * DF.
   *
   * @param calypsoCardClass Indicates which CLA byte should be used for the Apdu.
   * @param productType The target product type.
   * @param lid The LID.
   * @since 2.0.1
   */
  CmdCardSelectFile(
      CalypsoCardClass calypsoCardClass, CalypsoCard.ProductType productType, short lid) {
    super(commandRef, 0, null, null, null);
    buildCommand(calypsoCardClass, productType, lid);
  }

  /**
   * Builds the command.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param selectFileControl the selection mode control: FIRST, NEXT or CURRENT.
   */
  private void buildCommand(
      CalypsoCardClass calypsoCardClass, SelectFileControl selectFileControl) {
    byte cla = calypsoCardClass.getValue();
    byte p1;
    byte p2;
    byte[] selectData = new byte[] {0x00, 0x00};
    switch (selectFileControl) {
      case FIRST_EF:
        p1 = 0x02;
        p2 = 0x00;
        break;
      case NEXT_EF:
        p1 = 0x02;
        p2 = 0x02;
        break;
      case CURRENT_DF:
        // CL-KEY-KIFSF.1
        p1 = 0x09;
        p2 = 0x00;
        break;
      default:
        throw new IllegalStateException(
            "Unsupported selectFileControl parameter " + selectFileControl.name());
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, commandRef.getInstructionByte(), p1, p2, selectData, (byte) 0x00)));

    if (logger.isDebugEnabled()) {
      addSubName("SELECTIONCONTROL" + selectFileControl);
    }
  }

  /**
   * Builds the command.
   *
   * @param calypsoCardClass Indicates which CLA byte should be used for the Apdu.
   * @param productType The target product type.
   * @param lid The LID.
   */
  private void buildCommand(
      CalypsoCardClass calypsoCardClass, CalypsoCard.ProductType productType, short lid) {
    // handle the REV1 case
    // CL-KEY-KIFSF.1
    // If legacy and rev2 then 02h else if legacy then 08h else 09h
    byte p1;
    if (calypsoCardClass == CalypsoCardClass.LEGACY
        && productType == CalypsoCard.ProductType.PRIME_REVISION_2) {
      p1 = 0x02;
    } else if (calypsoCardClass == CalypsoCardClass.LEGACY) {
      p1 = 0x08;
    } else {
      p1 = 0x09;
    }

    byte[] dataIn = ByteArrayUtil.extractBytes(lid, 2);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(),
                commandRef.getInstructionByte(),
                p1,
                (byte) 0x00,
                dataIn,
                (byte) 0x00)));

    if (logger.isDebugEnabled()) {
      addSubName("LID=" + HexUtil.toHex(dataIn));
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.3
   */
  @Override
  void setApduResponseAndCheckStatus(ApduResponseApi apduResponse) throws CardCommandException {
    super.setApduResponseAndCheckStatus(apduResponse);
    parseProprietaryInformation(apduResponse.getDataOut(), getCalypsoCard());
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
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void finalizeRequest() {
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean isCryptoServiceRequiredToFinalizeRequest() {
    return getCommandContext().isEncryptionActive();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean synchronizeCryptoServiceBeforeCardProcessing() {
    return !getCommandContext().isSecureSessionOpen();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CardCommandException {
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    try {
      super.setApduResponseAndCheckStatus(apduResponse);
    } catch (CardDataAccessException e) {
      throw new SelectFileException("File not found", e);
    }
    parseProprietaryInformation(apduResponse.getDataOut(), getTransactionContext().getCard());
    updateTerminalSessionMacIfNeeded();
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
   * Parses the proprietary information and updates the corresponding Calypso card.
   *
   * @param dataOut The dataOut block to parse.
   * @param calypsoCard The Calypso card to update.
   * @since 2.2.3
   */
  static void parseProprietaryInformation(byte[] dataOut, CalypsoCardAdapter calypsoCard) {
    byte[] proprietaryInformation = getProprietaryInformation(dataOut);
    byte sfi = proprietaryInformation[SEL_SFI_OFFSET];
    byte fileType = proprietaryInformation[SEL_TYPE_OFFSET];
    switch (fileType) {
      case FILE_TYPE_MF:
      case FILE_TYPE_DF:
        DirectoryHeader directoryHeader =
            createDirectoryHeader(proprietaryInformation, calypsoCard);
        calypsoCard.setDirectoryHeader(directoryHeader);
        break;
      case FILE_TYPE_EF:
        FileHeaderAdapter fileHeader = createFileHeader(proprietaryInformation, calypsoCard);
        calypsoCard.setFileHeader(sfi, fileHeader);
        break;
      default:
        throw new IllegalStateException(String.format("Unknown file type: %02Xh", fileType));
    }
  }

  /**
   * @return The content of the proprietary information tag present in the response to the Select
   *     File command
   */
  private static byte[] getProprietaryInformation(byte[] dataOut) {
    byte[] proprietaryInformation;
    Map<Integer, byte[]> tags = BerTlvUtil.parseSimple(dataOut, true);
    proprietaryInformation = tags.get(TAG_PROPRIETARY_INFORMATION);
    if (proprietaryInformation == null) {
      throw new IllegalStateException("Proprietary information: tag not found.");
    }
    Assert.getInstance().isEqual(proprietaryInformation.length, 23, "proprietaryInformation");
    return proprietaryInformation;
  }

  /**
   * Parses the proprietaryInformation field of a file identified as an DF and create a {@link
   * DirectoryHeader}
   *
   * @param proprietaryInformation from the response to a Select File command.
   * @param calypsoCard the Calypso card.
   * @return A {@link DirectoryHeader} object
   */
  private static DirectoryHeader createDirectoryHeader(
      byte[] proprietaryInformation, CalypsoCardAdapter calypsoCard) {

    byte[] accessConditions = new byte[SEL_AC_LENGTH];
    System.arraycopy(proprietaryInformation, SEL_AC_OFFSET, accessConditions, 0, SEL_AC_LENGTH);

    byte[] keyIndexes = new byte[SEL_NKEY_LENGTH];
    System.arraycopy(proprietaryInformation, SEL_NKEY_OFFSET, keyIndexes, 0, SEL_NKEY_LENGTH);

    byte dfStatus = proprietaryInformation[SEL_DF_STATUS_OFFSET];

    int lidOffset =
        calypsoCard.getProductType() == CalypsoCard.ProductType.PRIME_REVISION_2
            ? SEL_LID_OFFSET_REV2
            : SEL_LID_OFFSET;

    short lid = ByteArrayUtil.extractShort(proprietaryInformation, lidOffset);

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
   * Parses the proprietaryInformation field of a file identified as an EF and create a {@link
   * FileHeaderAdapter}
   *
   * @param proprietaryInformation from the response to a Select File command.
   * @param calypsoCard the Calypso card.
   * @return A {@link FileHeaderAdapter} object
   */
  private static FileHeaderAdapter createFileHeader(
      byte[] proprietaryInformation, CalypsoCardAdapter calypsoCard) {

    ElementaryFile.Type fileType =
        getEfTypeFromCardValue(proprietaryInformation[SEL_EF_TYPE_OFFSET]);

    int recordSize;
    int recordsNumber;
    if (fileType == ElementaryFile.Type.BINARY) {
      recordSize = ByteArrayUtil.extractInt(proprietaryInformation, SEL_REC_SIZE_OFFSET, 2, false);
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

    short sharedReference = ByteArrayUtil.extractShort(proprietaryInformation, SEL_DATA_REF_OFFSET);

    int lidOffset =
        calypsoCard.getProductType() == CalypsoCard.ProductType.PRIME_REVISION_2
            ? SEL_LID_OFFSET_REV2
            : SEL_LID_OFFSET;

    short lid = ByteArrayUtil.extractShort(proprietaryInformation, lidOffset);

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
}
