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

import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.junit.Test;

public class CmdCardGetDataTraceabilityInformationTest {

  @Test
  public void getCommandRef_shouldReturn_GET_DATA() {
    CmdCardGetDataTraceabilityInformation cardCommand =
        new CmdCardGetDataTraceabilityInformation(CalypsoCardClass.ISO);
    assertThat(cardCommand.getCommandRef()).isEqualTo(CalypsoCardCommand.GET_DATA);
  }

  @Test
  public void getApduRequest_shouldReturn_wellFormedApdu() {
    CmdCardGetDataTraceabilityInformation cardCommand =
        new CmdCardGetDataTraceabilityInformation(CalypsoCardClass.ISO);
    assertThat(cardCommand.getApduRequest().getApdu())
        .isEqualTo(ByteArrayUtil.fromHex("00CA018500"));
  }

  @Test
  public void isSessionBufferUsed_shouldReturn_false() {
    CmdCardGetDataTraceabilityInformation cardCommand =
        new CmdCardGetDataTraceabilityInformation(CalypsoCardClass.ISO);
    assertThat(cardCommand.isSessionBufferUsed()).isFalse();
  }
}
