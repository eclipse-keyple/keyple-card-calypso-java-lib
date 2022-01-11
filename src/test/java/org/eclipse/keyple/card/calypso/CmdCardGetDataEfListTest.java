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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.calypso.card.FileHeader;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.junit.Test;

public class CmdCardGetDataEfListTest {

  @Test
  public void getCommandRef_shouldReturn_GET_DATA() {
    CmdCardGetDataEfList cardCommand = new CmdCardGetDataEfList(CalypsoCardClass.ISO);
    assertThat(cardCommand.getCommandRef()).isEqualTo(CalypsoCardCommand.GET_DATA);
  }

  @Test
  public void getApduRequest_shouldReturn_wellFormedApdu() {
    CmdCardGetDataEfList cardCommand = new CmdCardGetDataEfList(CalypsoCardClass.ISO);
    assertThat(cardCommand.getApduRequest().getApdu())
        .isEqualTo(ByteArrayUtil.fromHex("00CA00C000"));
  }

  @Test
  public void isSessionBufferUsed_shouldReturn_false() {
    CmdCardGetDataEfList cardCommand = new CmdCardGetDataEfList(CalypsoCardClass.ISO);
    assertThat(cardCommand.isSessionBufferUsed()).isFalse();
  }

  @Test
  public void getEfHeaders_shouldReturnEfDescriptorSet() {
    CmdCardGetDataEfList cardCommand = new CmdCardGetDataEfList(CalypsoCardClass.ISO);
    cardCommand.setApduResponse(
        new ApduResponseAdapter(
            ByteArrayUtil.fromHex(
                "C028C106200107021D01C10620FF09011D04C106F1231004F3F4C106F1231108F3F4C106F1231F09F3F49000")));
    Map<Byte, FileHeader> sfiToFileHeaderMap = cardCommand.getEfHeaders();
    assertThat(sfiToFileHeaderMap).hasSize(5);
    assertThat(sfiToFileHeaderMap.get((byte) 0x07).getLid()).isEqualTo((short) 0x2001);
    assertThat(sfiToFileHeaderMap.get((byte) 0x07).getEfType())
        .isEqualTo(ElementaryFile.Type.LINEAR);
    assertThat(sfiToFileHeaderMap.get((byte) 0x07).getRecordSize()).isEqualTo((byte) 0x1D);
    assertThat(sfiToFileHeaderMap.get((byte) 0x07).getRecordsNumber()).isEqualTo((byte) 0x01);
    assertThat(sfiToFileHeaderMap.get((byte) 0x09).getLid()).isEqualTo((short) 0x20FF);
    assertThat(sfiToFileHeaderMap.get((byte) 0x09).getEfType())
        .isEqualTo(ElementaryFile.Type.BINARY);
    assertThat(sfiToFileHeaderMap.get((byte) 0x09).getRecordSize()).isEqualTo((byte) 0x1D);
    assertThat(sfiToFileHeaderMap.get((byte) 0x09).getRecordsNumber()).isEqualTo((byte) 0x04);
    assertThat(sfiToFileHeaderMap.get((byte) 0x10).getLid()).isEqualTo((short) 0xF123);
    assertThat(sfiToFileHeaderMap.get((byte) 0x10).getEfType())
        .isEqualTo(ElementaryFile.Type.CYCLIC);
    assertThat(sfiToFileHeaderMap.get((byte) 0x10).getRecordSize()).isEqualTo((byte) 0xF3);
    assertThat(sfiToFileHeaderMap.get((byte) 0x10).getRecordsNumber()).isEqualTo((byte) 0xF4);
    assertThat(sfiToFileHeaderMap.get((byte) 0x11).getLid()).isEqualTo((short) 0xF123);
    assertThat(sfiToFileHeaderMap.get((byte) 0x11).getEfType())
        .isEqualTo(ElementaryFile.Type.SIMULATED_COUNTERS);
    assertThat(sfiToFileHeaderMap.get((byte) 0x11).getRecordSize()).isEqualTo((byte) 0xF3);
    assertThat(sfiToFileHeaderMap.get((byte) 0x11).getRecordsNumber()).isEqualTo((byte) 0xF4);
    assertThat(sfiToFileHeaderMap.get((byte) 0x1F).getLid()).isEqualTo((short) 0xF123);
    assertThat(sfiToFileHeaderMap.get((byte) 0x1F).getEfType())
        .isEqualTo(ElementaryFile.Type.COUNTERS);
    assertThat(sfiToFileHeaderMap.get((byte) 0x1F).getRecordSize()).isEqualTo((byte) 0xF3);
    assertThat(sfiToFileHeaderMap.get((byte) 0x1F).getRecordsNumber()).isEqualTo((byte) 0xF4);
  }

  @Test(expected = IllegalStateException.class)
  public void getEfHeaders_whenNoResponseData_shouldISE() {
    CmdCardGetDataEfList cardCommand = new CmdCardGetDataEfList(CalypsoCardClass.ISO);
    cardCommand.setApduResponse(new ApduResponseAdapter(ByteArrayUtil.fromHex("1234")));
    cardCommand.getEfHeaders();
  }

  @Test(expected = IllegalStateException.class)
  public void getEfHeaders_whenBadTagC0Id_shouldISE() {
    CmdCardGetDataEfList cardCommand = new CmdCardGetDataEfList(CalypsoCardClass.ISO);
    cardCommand.setApduResponse(
        new ApduResponseAdapter(ByteArrayUtil.fromHex("C208C1061122010255669000")));
    cardCommand.getEfHeaders();
  }

  @Test(expected = IllegalStateException.class)
  public void getEfHeaders_whenBadTagC0Length_shouldISE() {
    CmdCardGetDataEfList cardCommand = new CmdCardGetDataEfList(CalypsoCardClass.ISO);
    cardCommand.setApduResponse(
        new ApduResponseAdapter(ByteArrayUtil.fromHex("C006C1061122010255669000")));
    cardCommand.getEfHeaders();
  }

  @Test(expected = IllegalStateException.class)
  public void getEfHeaders_whenBadTagC1Id_shouldISE() {
    CmdCardGetDataEfList cardCommand = new CmdCardGetDataEfList(CalypsoCardClass.ISO);
    cardCommand.setApduResponse(
        new ApduResponseAdapter(ByteArrayUtil.fromHex("C008C2061122010255669000")));
    cardCommand.getEfHeaders();
  }

  @Test(expected = IllegalStateException.class)
  public void getEfHeaders_whenBadTagC1Length_shouldISE() {
    CmdCardGetDataEfList cardCommand = new CmdCardGetDataEfList(CalypsoCardClass.ISO);
    cardCommand.setApduResponse(
        new ApduResponseAdapter(ByteArrayUtil.fromHex("C008C10811220102556677889000")));
    cardCommand.getEfHeaders();
  }

  @Test(expected = IllegalStateException.class)
  public void getEfHeaders_whenBadLength_shouldISE() {
    CmdCardGetDataEfList cardCommand = new CmdCardGetDataEfList(CalypsoCardClass.ISO);
    cardCommand.setApduResponse(
        new ApduResponseAdapter(ByteArrayUtil.fromHex("C008C10611220102556677889000")));
    cardCommand.getEfHeaders();
  }

  @Test(expected = IllegalArgumentException.class)
  public void getEfHeaders_whenBadSfi_shouldIAE() {
    CmdCardGetDataEfList cardCommand = new CmdCardGetDataEfList(CalypsoCardClass.ISO);
    cardCommand.setApduResponse(
        new ApduResponseAdapter(ByteArrayUtil.fromHex("C008C1061122200255669000")));
    cardCommand.getEfHeaders();
  }

  @Test(expected = IllegalStateException.class)
  public void getEfHeaders_whenBadEfType_shouldISE() {
    CmdCardGetDataEfList cardCommand = new CmdCardGetDataEfList(CalypsoCardClass.ISO);
    cardCommand.setApduResponse(
        new ApduResponseAdapter(ByteArrayUtil.fromHex("C008C1061122010355669000")));
    cardCommand.getEfHeaders();
  }
}
