/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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

import java.util.Arrays;
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.junit.Before;
import org.junit.Test;

public class CalypsoCardAdapterTest {

  private CalypsoCardAdapter calypsoCardAdapter;
  public static final String CALYPSO_SERIAL_NUMBER = "0000000012345678";
  public static final String POWER_ON_DATA =
      "3B8F8001805A0A0103200311" + CALYPSO_SERIAL_NUMBER.substring(8) + "829000F7";
  public static final String POWER_ON_DATA_BAD_LENGTH =
      "3B8F8001805A0A010320031124B77FE7829000F700";

  public static final String DF_NAME = "315449432E49434131";
  public static final String STARTUP_INFO_APP_TYPE_XX = "0A3C%02X05141001";
  public static final String STARTUP_INFO_APP_TYPE_00 = "0A3C0005141001";
  public static final String STARTUP_INFO_APP_TYPE_FF = "0A3CFF05141001";
  public static final int SW1SW2_OK = 0x9000;

  @Before
  public void setUp() {
    calypsoCardAdapter = new CalypsoCardAdapter();
  }

  @Test(expected = IllegalArgumentException.class)
  public void initializeWithPowerOnData_whenInconsistentData_shouldThrowIAE() {
    calypsoCardAdapter.initializeWithPowerOnData(POWER_ON_DATA_BAD_LENGTH);
  }

  @Test
  public void initializeWithPowerOnData_shouldInitPrimeRevision1ProductType() {
    calypsoCardAdapter.initializeWithPowerOnData(POWER_ON_DATA);
    assertThat(calypsoCardAdapter.getProductType())
        .isEqualTo(CalypsoCard.ProductType.PRIME_REVISION_1);
    assertThat(calypsoCardAdapter.isExtendedModeSupported()).isFalse();
    assertThat(calypsoCardAdapter.isSvFeatureAvailable()).isFalse();
    assertThat(calypsoCardAdapter.isPinFeatureAvailable()).isFalse();
    assertThat(calypsoCardAdapter.isPkiModeSupported()).isFalse();
    assertThat(calypsoCardAdapter.isDfInvalidated()).isFalse();
    assertThat(calypsoCardAdapter.isRatificationOnDeselectSupported()).isTrue();
    assertThat(calypsoCardAdapter.getApplicationSerialNumber())
        .isEqualTo(ByteArrayUtil.fromHex(CALYPSO_SERIAL_NUMBER));
  }

  @Test(expected = IllegalArgumentException.class)
  public void initializeWithFci_whenBadFci_shouldThrowIAE() {
    ApduResponseApi selectApplicationResponse =
        new ApduResponseAdapter(ByteArrayUtil.fromHex("1122339000"));
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
  }

  @Test
  public void initializeWithFci_withEmptyFCI_shouldInitUnknownProductType() {
    ApduResponseApi selectApplicationResponse =
        new ApduResponseAdapter(ByteArrayUtil.fromHex("9000"));
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getProductType()).isEqualTo(CalypsoCard.ProductType.UNKNOWN);
  }

  @Test(expected = IllegalArgumentException.class)
  public void initializeWithFci_whenAppTypeIs_00_shouldThrowIAE() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_APP_TYPE_00, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
  }

  @Test
  public void initializeWithFci_whenAppTypeIs_FF_shouldInitUnknownProductType() {
    ApduResponseApi selectApplicationResponse =
            buildSelectApplicationResponse(
                    DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_APP_TYPE_FF, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getProductType()).isEqualTo(CalypsoCard.ProductType.UNKNOWN);
  }

  @Test
  public void
      initializeWithFci_whenAppTypeIsBetween_01_and_1F_shouldInitPrimeRevision2ProductType() {
    ApduResponseApi selectApplicationResponse;
    for(int appType=1; appType <= 0x1F; appType++) {
      selectApplicationResponse =
              buildSelectApplicationResponse(
                      DF_NAME, CALYPSO_SERIAL_NUMBER, String.format(STARTUP_INFO_APP_TYPE_XX, appType), SW1SW2_OK);
      calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
      assertThat(calypsoCardAdapter.getProductType()).isEqualTo(CalypsoCard.ProductType.PRIME_REVISION_2);
    }
  }

  @Test
  public void
  initializeWithFci_whenAppTypeIsBetween_20_and_89_shouldInitPrimeRevision3ProductType() {
    ApduResponseApi selectApplicationResponse;
    for(int appType=0x20; appType <= 0x89; appType++) {
      selectApplicationResponse =
              buildSelectApplicationResponse(
                      DF_NAME, CALYPSO_SERIAL_NUMBER, String.format(STARTUP_INFO_APP_TYPE_XX, appType), SW1SW2_OK);
      calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
      assertThat(calypsoCardAdapter.getProductType()).isEqualTo(CalypsoCard.ProductType.PRIME_REVISION_3);
    }
  }

  @Test
  public void
  initializeWithFci_whenAppTypeIsBetween_90_and_97_shouldInitLightProductType() {
    ApduResponseApi selectApplicationResponse;
    for(int appType=0x90; appType <= 0x97; appType++) {
      selectApplicationResponse =
              buildSelectApplicationResponse(
                      DF_NAME, CALYPSO_SERIAL_NUMBER, String.format(STARTUP_INFO_APP_TYPE_XX, appType), SW1SW2_OK);
      calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
      assertThat(calypsoCardAdapter.getProductType()).isEqualTo(CalypsoCard.ProductType.LIGHT);
    }
  }

  @Test
  public void
  initializeWithFci_whenAppTypeIsBetween_98_and_9F_shouldInitBasicProductType() {
    ApduResponseApi selectApplicationResponse;
    for(int appType=0x98; appType <= 0x9F; appType++) {
      selectApplicationResponse =
              buildSelectApplicationResponse(
                      DF_NAME, CALYPSO_SERIAL_NUMBER, String.format(STARTUP_INFO_APP_TYPE_XX, appType), SW1SW2_OK);
      calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
      assertThat(calypsoCardAdapter.getProductType()).isEqualTo(CalypsoCard.ProductType.BASIC);
    }
  }

  @Test
  public void
  initializeWithFci_whenAppTypeIsBetween_A0_and_FE_shouldInitPrimeRevision3ProductType() {
    ApduResponseApi selectApplicationResponse;
    for(int appType=0xA0; appType <= 0xFE; appType++) {
      selectApplicationResponse =
              buildSelectApplicationResponse(
                      DF_NAME, CALYPSO_SERIAL_NUMBER, String.format(STARTUP_INFO_APP_TYPE_XX, appType), SW1SW2_OK);
      calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
      assertThat(calypsoCardAdapter.getProductType()).isEqualTo(CalypsoCard.ProductType.PRIME_REVISION_3);
    }
  }

  private ApduResponseApi buildSelectApplicationResponse(
      String dfNameAsHexString,
      String serialNumberAsHexString,
      String startupInfoAsHexString,
      int statusWord) {
    String FCI = "6F238409315449432E49434131A516BF0C13C70800000000C16B293F53070A3C23051410019000";
    byte[] dfName = ByteArrayUtil.fromHex(dfNameAsHexString);
    byte[] serialNumber = ByteArrayUtil.fromHex(serialNumberAsHexString);
    byte[] startupInfo = ByteArrayUtil.fromHex(startupInfoAsHexString);
    byte[] selAppResponse = new byte[30 + dfName.length];
    selAppResponse[0] = (byte) 0x6F;
    selAppResponse[1] = (byte) (26 + dfName.length);
    selAppResponse[2] = (byte) 0x84;
    selAppResponse[3] = (byte) (dfName.length);
    System.arraycopy(dfName, 0, selAppResponse, 4, dfName.length);
    selAppResponse[4 + dfName.length] = (byte) 0xA5;
    selAppResponse[5 + dfName.length] = (byte) 0x16;
    selAppResponse[6 + dfName.length] = (byte) 0xBF;
    selAppResponse[7 + dfName.length] = (byte) 0x0C;
    selAppResponse[8 + dfName.length] = (byte) 0x13;
    selAppResponse[9 + dfName.length] = (byte) 0xC7;
    selAppResponse[10 + dfName.length] = (byte) 0x08;
    System.arraycopy(serialNumber, 0, selAppResponse, 11 + dfName.length, 8);
    selAppResponse[19 + dfName.length] = (byte) 0x53;
    selAppResponse[20 + dfName.length] = (byte) 0x07;
    System.arraycopy(startupInfo, 0, selAppResponse, 21 + dfName.length, 7);
    selAppResponse[28 + dfName.length] = (byte) ((statusWord & 0xFF00) >> 8);
    selAppResponse[29 + dfName.length] = (byte) (statusWord & 0xFF);
    return new ApduResponseAdapter(selAppResponse);
  }

  /**
   * (private)<br>
   * Adapter of {@link ApduResponseApi}.
   */
  private static class ApduResponseAdapter implements ApduResponseApi {

    private final byte[] apdu;
    private final int statusWord;

    /** Constructor */
    public ApduResponseAdapter(byte[] apdu) {
      this.apdu = apdu;
      statusWord =
          ((apdu[apdu.length - 2] & 0x000000FF) << 8) + (apdu[apdu.length - 1] & 0x000000FF);
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getApdu() {
      return apdu;
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getDataOut() {
      return Arrays.copyOfRange(this.apdu, 0, this.apdu.length - 2);
    }

    /** {@inheritDoc} */
    @Override
    public int getStatusWord() {
      return statusWord;
    }
  }
}
