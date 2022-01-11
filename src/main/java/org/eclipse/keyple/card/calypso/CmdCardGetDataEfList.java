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

import java.util.*;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.calypso.card.FileHeader;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.Assert;

/**
 * (package-private)<br>
 * Builds the Get data APDU commands for the EF LIST tag.
 *
 * <p>In contact mode, this command can not be sent in a secure session because it would generate a
 * 6Cxx status and thus make calculation of the digest impossible.
 *
 * @since 2.0.1
 */
final class CmdCardGetDataEfList extends AbstractCardCommand {

  private static final CalypsoCardCommand command = CalypsoCardCommand.GET_DATA;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
    m.put(
        0x6A88,
        new StatusProperties(
            "Data object not found (optional mode not available).", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardDataAccessException.class));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardGetDataEfList.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @since 2.0.1
   */
  CmdCardGetDataEfList(CalypsoCardClass calypsoCardClass) {

    super(command);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(),
                command.getInstructionByte(),
                (byte) 0x00,
                (byte) 0xC0,
                null,
                (byte) 0x00)));
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
   * @since 2.0.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * (package-private)<br>
   * Gets a reference to a map of all Elementary File headers by their associated SFI.
   *
   * @return A not empty map.
   * @since 2.0.1
   * @throws IllegalStateException If there is an error in the data or TLV structure.
   * @throws IllegalArgumentException If one of the SFI is out of range.
   */
  Map<Byte, FileHeader> getEfHeaders() {
    byte[] rawList = getApduResponse().getDataOut();
    if (rawList.length < 2
        || rawList[0] != (byte) 0xC0
        || rawList.length != rawList[1] + 2
        || rawList[1] % 8 != 0) {
      throw new IllegalStateException("Bad EF List TLV structure.");
    }
    Map<Byte, FileHeader> efToFileHeaderMap = new HashMap<Byte, FileHeader>();
    int nbFiles = rawList[1] / 8;
    for (int i = 0; i < nbFiles; i++) {
      if (rawList[2 + i * 8] != (byte) (0xC1) || rawList[2 + i * 8 + 1] != 6) {
        throw new IllegalStateException("Bad EF descriptor tag.");
      }
      efToFileHeaderMap.put(
          rawList[4 + (i * 8) + 2],
          createFileHeader(Arrays.copyOfRange(rawList, 4 + (i * 8), 4 + (i * 8) + 6)));
    }
    return efToFileHeaderMap;
  }

  /**
   * (private) Creates a {@link FileHeader} from a 6-byte descriptor as defined by the GET DATA
   * command for the tag EF LIST.
   *
   * @param efDescriptorByteArray A 6-byte array.
   * @return A not null {@link FileHeader}.
   * @throws IllegalArgumentException If the SFI byte is out of range.
   * @throws IllegalStateException If the EF type byte does not match a known EF type.
   */
  private FileHeader createFileHeader(byte[] efDescriptorByteArray) {
    Assert.getInstance()
        .isInRange(
            (int) efDescriptorByteArray[2],
            CalypsoCardConstant.SFI_MIN,
            CalypsoCardConstant.SFI_MAX,
            "SFI");
    ElementaryFile.Type efType;
    switch (efDescriptorByteArray[3]) {
      case CalypsoCardConstant.EF_TYPE_BINARY:
        efType = ElementaryFile.Type.BINARY;
        break;
      case CalypsoCardConstant.EF_TYPE_LINEAR:
        efType = ElementaryFile.Type.LINEAR;
        break;
      case CalypsoCardConstant.EF_TYPE_CYCLIC:
        efType = ElementaryFile.Type.CYCLIC;
        break;
      case CalypsoCardConstant.EF_TYPE_SIMULATED_COUNTERS:
        efType = ElementaryFile.Type.SIMULATED_COUNTERS;
        break;
      case CalypsoCardConstant.EF_TYPE_COUNTERS:
        efType = ElementaryFile.Type.COUNTERS;
        break;
      default:
        throw new IllegalStateException("Unexpected EF type");
    }
    return FileHeaderAdapter.builder()
        .lid((short) (efDescriptorByteArray[0] << 8 | efDescriptorByteArray[1] & 0xFF))
        .type(efType)
        .recordSize(efDescriptorByteArray[4])
        .recordsNumber(efDescriptorByteArray[5])
        .build();
  }
}
