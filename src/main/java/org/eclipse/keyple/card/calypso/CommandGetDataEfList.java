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

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.util.*;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keypop.calypso.card.card.ElementaryFile;
import org.eclipse.keypop.calypso.card.card.FileHeader;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Get data APDU commands for the EF LIST tag.
 *
 * <p>In contact mode, this command can not be sent in a secure session because it would generate a
 * 6Cxx status and thus make calculation of the digest impossible.
 *
 * @since 2.1.0
 */
final class CommandGetDataEfList extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;
  private static final int DESCRIPTORS_OFFSET = 2;
  private static final int DESCRIPTOR_DATA_OFFSET = 2;
  private static final int DESCRIPTOR_DATA_SFI_OFFSET = 2;
  private static final int DESCRIPTOR_TAG_LENGTH = 8;
  private static final int DESCRIPTOR_DATA_LENGTH = 6;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(
        0x6A88,
        new StatusProperties(
            "Data object not found (optional mode not available)", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported", CardDataAccessException.class));
    STATUS_TABLE = m;
  }

  /**
   * Constructor.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @since 2.3.2
   */
  CommandGetDataEfList(TransactionContextDto transactionContext, CommandContextDto commandContext) {
    super(CardCommandRef.GET_DATA, MAXIMUM_DATA_LENGTH, transactionContext, commandContext);
    byte cardClass =
        transactionContext.getCard() != null
            ? transactionContext.getCard().getCardClass().getValue()
            : CalypsoCardClass.ISO.getValue();
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cardClass,
                getCommandRef().getInstructionByte(),
                CalypsoCardConstant.TAG_EF_LIST_MSB,
                CalypsoCardConstant.TAG_EF_LIST_LSB,
                NO_DATA_IN,
                ISO7816_LE_MAX)));
    addSubName("EF_LIST");
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
    super.setApduResponseAndCheckStatus(apduResponse);
    Map<FileHeaderAdapter, Byte> fileHeaderToSfiMap = getEfHeaders();
    for (Map.Entry<FileHeaderAdapter, Byte> entry : fileHeaderToSfiMap.entrySet()) {
      getTransactionContext().getCard().setFileHeader(entry.getValue(), entry.getKey());
    }
    updateTerminalSessionIfNeeded();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * Gets a reference to a map of all Elementary File headers and their associated SFI.
   *
   * @return A not empty map.
   * @since 2.1.0
   */
  private Map<FileHeaderAdapter, Byte> getEfHeaders() {
    byte[] rawList = getApduResponse().getDataOut();
    Map<FileHeaderAdapter, Byte> fileHeaderToSfiMap = new HashMap<>();
    int nbFiles = rawList[1] / DESCRIPTOR_TAG_LENGTH;
    for (int i = 0; i < nbFiles; i++) {
      fileHeaderToSfiMap.put(
          createFileHeader(
              Arrays.copyOfRange(
                  rawList,
                  DESCRIPTORS_OFFSET + (i * DESCRIPTOR_TAG_LENGTH) + DESCRIPTOR_DATA_OFFSET,
                  DESCRIPTORS_OFFSET
                      + (i * DESCRIPTOR_TAG_LENGTH)
                      + DESCRIPTOR_DATA_OFFSET
                      + DESCRIPTOR_DATA_LENGTH)),
          rawList[
              DESCRIPTORS_OFFSET
                  + (i * DESCRIPTOR_TAG_LENGTH)
                  + DESCRIPTOR_DATA_OFFSET
                  + DESCRIPTOR_DATA_SFI_OFFSET]);
    }
    return fileHeaderToSfiMap;
  }

  /**
   * (private) Creates a {@link FileHeader} from a 6-byte descriptor as defined by the GET DATA
   * command for the tag EF LIST.
   *
   * @param efDescriptorByteArray A 6-byte array.
   * @return A not null {@link FileHeader}.
   */
  private static FileHeaderAdapter createFileHeader(byte[] efDescriptorByteArray) {
    ElementaryFile.Type efType;
    switch (efDescriptorByteArray[3]) {
      case CalypsoCardConstant.EF_TYPE_LINEAR:
        efType = ElementaryFile.Type.LINEAR;
        break;
      case CalypsoCardConstant.EF_TYPE_CYCLIC:
        efType = ElementaryFile.Type.CYCLIC;
        break;
      case CalypsoCardConstant.EF_TYPE_COUNTERS:
        efType = ElementaryFile.Type.COUNTERS;
        break;
      case CalypsoCardConstant.EF_TYPE_BINARY:
        efType = ElementaryFile.Type.BINARY;
        break;
      case CalypsoCardConstant.EF_TYPE_SIMULATED_COUNTERS:
        efType = ElementaryFile.Type.SIMULATED_COUNTERS;
        break;
      default:
        throw new IllegalStateException("Unexpected EF type");
    }
    return FileHeaderAdapter.builder()
        .lid(ByteArrayUtil.extractShort(efDescriptorByteArray, 0))
        .type(efType)
        .recordSize(efDescriptorByteArray[4])
        .recordsNumber(efDescriptorByteArray[5])
        .build();
  }
}
