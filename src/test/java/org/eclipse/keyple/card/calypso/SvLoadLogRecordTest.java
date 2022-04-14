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

import static org.assertj.core.api.Assertions.assertThat;

import org.eclipse.keyple.core.util.HexUtil;
import org.junit.Before;
import org.junit.Test;

public class SvLoadLogRecordTest {

  SvLoadLogRecordAdapter svLoadLogRecordAdapter;

  private static final String HEADER = "79007013DE31A75F00001A";
  private static final String AMOUNT_STR = "FFFFFE";
  private static final String DATE_STR = "1234";
  private static final String TIME_STR = "5678";
  private static final String FREE1_STR = "41";
  private static final String FREE2_STR = "42";
  private static final String KVC_STR = "90";
  private static final String SAMID_STR = "AABBCCDD";

  private static final int AMOUNT = -2;
  private static final byte[] DATE = HexUtil.toByteArray(DATE_STR);
  private static final byte[] TIME = HexUtil.toByteArray(TIME_STR);
  private static final byte[] FREE = HexUtil.toByteArray(FREE1_STR + FREE2_STR);
  private static final byte KVC = (byte) 0x90;
  private static final byte[] SAMID = HexUtil.toByteArray(SAMID_STR);
  private static final int SAM_TNUM = 0x123456;
  private static final int BALANCE = 0x445566;
  private static final int SV_TNUM = 0x7890;

  private static final String BALANCE_STR = String.format("%06X", BALANCE);
  private static final String SAM_TNUM_STR = String.format("%06X", SAM_TNUM);
  private static final String SV_TNUM_STR = String.format("%04X", SV_TNUM);

  @Before
  public void setUp() {
    byte[] svGetLoadData =
        HexUtil.toByteArray(
            HEADER
                + DATE_STR
                + FREE1_STR
                + KVC_STR
                + FREE2_STR
                + BALANCE_STR
                + AMOUNT_STR
                + TIME_STR
                + SAMID_STR
                + SAM_TNUM_STR
                + SV_TNUM_STR);
    svLoadLogRecordAdapter = new SvLoadLogRecordAdapter(svGetLoadData, HEADER.length() / 2);
  }

  @Test
  public void getAmount_shouldReturnAmount() {
    assertThat(svLoadLogRecordAdapter.getAmount()).isEqualTo(AMOUNT);
  }

  @Test
  public void getBalance_shouldReturnBalance() {
    assertThat(svLoadLogRecordAdapter.getBalance()).isEqualTo(BALANCE);
  }

  @Test
  public void getLoadDate_shouldReturnLoadDate() {
    assertThat(svLoadLogRecordAdapter.getLoadDate()).isEqualTo(DATE);
  }

  @Test
  public void getLoadTime_shouldReturnLoadTime() {
    assertThat(svLoadLogRecordAdapter.getLoadTime()).isEqualTo(TIME);
  }

  @Test
  public void getFreeData_shouldReturnFreeData() {
    assertThat(svLoadLogRecordAdapter.getFreeData()).isEqualTo(FREE);
  }

  @Test
  public void getKvc_shouldReturnKvc() {
    assertThat(svLoadLogRecordAdapter.getKvc()).isEqualTo(KVC);
  }

  @Test
  public void getSamId_shouldReturnSamId() {
    assertThat(svLoadLogRecordAdapter.getSamId()).isEqualTo(SAMID);
  }

  @Test
  public void getSamTNum_shouldReturnSamTNum() {
    assertThat(svLoadLogRecordAdapter.getSamTNum()).isEqualTo(SAM_TNUM);
  }

  @Test
  public void getSvTNum_shouldReturnSvTNum() {
    assertThat(svLoadLogRecordAdapter.getSvTNum()).isEqualTo(SV_TNUM);
  }

  @Test
  public void toString_shouldContainSamID() {
    assertThat(svLoadLogRecordAdapter.toString()).contains(SAMID_STR);
  }
}
