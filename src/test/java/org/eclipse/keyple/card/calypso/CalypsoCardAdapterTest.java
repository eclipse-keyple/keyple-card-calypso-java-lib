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

import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.junit.Before;
import org.junit.Test;

public class CalypsoCardAdapterTest {

  private CalypsoCardAdapter calypsoCardAdapter;
  private static final String CALYPSO_SERIAL_NUMBER = "0000000012345678";
  private static final String CALYPSO_SERIAL_NUMBER_HCE = "12340080FEDCBA98";
  private static final String POWER_ON_DATA =
      "3B8F8001805A0A0103200311" + CALYPSO_SERIAL_NUMBER.substring(8) + "829000F7";
  private static final String POWER_ON_DATA_BAD_LENGTH =
      "3B8F8001805A0A010320031124B77FE7829000F700";

  private static final String DF_NAME = "315449432E49434131";
  private static final String STARTUP_INFO_PRIME_REVISION_2 = "0A3C1005141001";
  private static final String STARTUP_INFO_PRIME_REVISION_3 = "0A3C2005141001";
  private static final String STARTUP_INFO_TOO_SHORT = "0A3C20051410";
  private static final String STARTUP_INFO_PRIME_REVISION_3_EXTRA_BYTE = "0A3C2005141001FF";
  private static final String STARTUP_INFO_PRIME_REVISION_3_PIN = "0A3C2105141001";
  private static final String STARTUP_INFO_PRIME_REVISION_3_STORED_VALUE = "0A3C2205141001";
  private static final String STARTUP_INFO_PRIME_REVISION_3_RATIFICATION_ON_DESELECT =
      "0A3C2405141001";
  private static final String STARTUP_INFO_PRIME_REVISION_3_EXTENDED_MODE = "0A3C2805141001";
  private static final String STARTUP_INFO_PRIME_REVISION_3_PKI_MODE = "0A3C3005141001";
  private static final String STARTUP_INFO_SESSION_MODIFICATION_XX = "%02X3C2005141001";
  private static final String STARTUP_INFO_PLATFORM_XX = "0A%02X2005141001";
  private static final String STARTUP_INFO_APP_TYPE_XX = "0A3C%02X05141001";
  private static final String STARTUP_INFO_BASIC_APP_TYPE_XX = "043C%02X05141001";
  private static final String STARTUP_INFO_SUBTYPE_XX = "0A3C20%02X141001";
  private static final String STARTUP_INFO_SOFTWARE_ISSUER_XX = "0A3C2005%02X1001";
  private static final String STARTUP_INFO_SOFTWARE_VERSION_XX = "0A3C200514%02X01";
  private static final String STARTUP_INFO_SOFTWARE_REVISION_XX = "0A3C20051410%02X";
  private static final String STARTUP_INFO_APP_TYPE_00 = "0A3C0005141001";
  private static final String STARTUP_INFO_APP_TYPE_FF = "0A3CFF05141001";
  private static final int SW1SW2_OK = 0x9000;
  private static final int SW1SW2_INVALIDATED = 0x6283;
  private final String SELECT_APPLICATION_RESPONSE_DIFFERENT_TAGS_ORDER =
      "6F23A516BF0C1353070A3C2005141001C70800000000123456788409315449432E494341319000";

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
    for (int appType = 1; appType <= 0x1F; appType++) {
      selectApplicationResponse =
          buildSelectApplicationResponse(
              DF_NAME,
              CALYPSO_SERIAL_NUMBER,
              String.format(STARTUP_INFO_APP_TYPE_XX, appType),
              SW1SW2_OK);
      calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
      assertThat(calypsoCardAdapter.getProductType())
          .isEqualTo(CalypsoCard.ProductType.PRIME_REVISION_2);
    }
  }

  @Test
  public void
      initializeWithFci_whenAppTypeIsBetween_20_and_89_shouldInitPrimeRevision3ProductType() {
    ApduResponseApi selectApplicationResponse;
    for (int appType = 0x20; appType <= 0x89; appType++) {
      selectApplicationResponse =
          buildSelectApplicationResponse(
              DF_NAME,
              CALYPSO_SERIAL_NUMBER,
              String.format(STARTUP_INFO_APP_TYPE_XX, appType),
              SW1SW2_OK);
      calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
      assertThat(calypsoCardAdapter.getProductType())
          .isEqualTo(CalypsoCard.ProductType.PRIME_REVISION_3);
    }
  }

  @Test
  public void initializeWithFci_whenAppTypeIsBetween_90_and_97_shouldInitLightProductType() {
    ApduResponseApi selectApplicationResponse;
    for (int appType = 0x90; appType <= 0x97; appType++) {
      selectApplicationResponse =
          buildSelectApplicationResponse(
              DF_NAME,
              CALYPSO_SERIAL_NUMBER,
              String.format(STARTUP_INFO_APP_TYPE_XX, appType),
              SW1SW2_OK);
      calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
      assertThat(calypsoCardAdapter.getProductType()).isEqualTo(CalypsoCard.ProductType.LIGHT);
    }
  }

  @Test
  public void initializeWithFci_whenAppTypeIsBetween_98_and_9F_shouldInitBasicProductType() {
    ApduResponseApi selectApplicationResponse;
    for (int appType = 0x98; appType <= 0x9F; appType++) {
      selectApplicationResponse =
          buildSelectApplicationResponse(
              DF_NAME,
              CALYPSO_SERIAL_NUMBER,
              String.format(STARTUP_INFO_BASIC_APP_TYPE_XX, appType),
              SW1SW2_OK);
      calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
      assertThat(calypsoCardAdapter.getProductType()).isEqualTo(CalypsoCard.ProductType.BASIC);
    }
  }

  @Test
  public void
      initializeWithFci_whenAppTypeIsBetween_A0_and_FE_shouldInitPrimeRevision3ProductType() {
    ApduResponseApi selectApplicationResponse;
    for (int appType = 0xA0; appType <= 0xFE; appType++) {
      selectApplicationResponse =
          buildSelectApplicationResponse(
              DF_NAME,
              CALYPSO_SERIAL_NUMBER,
              String.format(STARTUP_INFO_APP_TYPE_XX, appType),
              SW1SW2_OK);
      calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
      assertThat(calypsoCardAdapter.getProductType())
          .isEqualTo(CalypsoCard.ProductType.PRIME_REVISION_3);
    }
  }

  @Test
  public void initializeWithFci_whenStatusWord_9000_shouldInitNotInvalidated() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isDfInvalidated()).isFalse();
  }

  @Test
  public void initializeWithFci_whenStatusWord_6283_shouldInitInvalidated() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_INVALIDATED);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isDfInvalidated()).isTrue();
  }

  @Test
  public void initializeWithFci_whenSerialNumberNotHce_shouldInitHceFalse() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isHce()).isFalse();
  }

  @Test
  public void initializeWithFci_whenSerialNumberHce_shouldInitHceTrue() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER_HCE, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isHce()).isTrue();
  }

  @Test(expected = IllegalArgumentException.class)
  public void initializeWithFci_whenSessionModificationByteIsOutOfRangeInf_shouldIAE() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER_HCE,
            String.format(STARTUP_INFO_SESSION_MODIFICATION_XX, (byte) 0x05),
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
  }

  @Test(expected = IllegalArgumentException.class)
  public void initializeWithFci_whenSessionModificationByteIsOutOfRangeSup_shouldIAE() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER_HCE,
            String.format(STARTUP_INFO_SESSION_MODIFICATION_XX, (byte) 0x38),
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
  }

  @Test(expected = IllegalArgumentException.class)
  public void initializeWithFci_whenStartupInfoIsShorter_shouldThrowParsingException() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER_HCE, STARTUP_INFO_TOO_SHORT, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
  }

  @Test
  public void initializeWithFci_whenStartupInfoIsLarger_shouldProvideWholeData() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER_HCE,
            STARTUP_INFO_PRIME_REVISION_3_EXTRA_BYTE,
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getStartupInfoRawData())
        .isEqualTo(ByteArrayUtil.fromHex(STARTUP_INFO_PRIME_REVISION_3_EXTRA_BYTE));
  }

  @Test
  public void initializeWithFci_whenTagsAreInADifferentOrder_shouldProvideSameResult() {
    ApduResponseApi selectApplicationResponse =
        new ApduResponseAdapter(
            ByteArrayUtil.fromHex(SELECT_APPLICATION_RESPONSE_DIFFERENT_TAGS_ORDER));
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getDfName()).isEqualTo(ByteArrayUtil.fromHex(DF_NAME));
    assertThat(calypsoCardAdapter.getCalypsoSerialNumberFull())
        .isEqualTo(ByteArrayUtil.fromHex(CALYPSO_SERIAL_NUMBER));
    assertThat(calypsoCardAdapter.getStartupInfoRawData())
        .isEqualTo(ByteArrayUtil.fromHex(STARTUP_INFO_PRIME_REVISION_3));
  }

  @Test
  public void getPowerOnData_whenNotSet_shouldReturnNull() {
    assertThat(calypsoCardAdapter.getPowerOnData()).isNull();
  }

  @Test
  public void getPowerOnData_shouldReturnPowerOnData() {
    calypsoCardAdapter.initializeWithPowerOnData(POWER_ON_DATA);
    assertThat(calypsoCardAdapter.getPowerOnData()).isEqualTo(POWER_ON_DATA);
  }

  @Test
  public void getSelectApplicationResponse_whenNotSet_shouldReturnEmpty() {
    assertThat(calypsoCardAdapter.getSelectApplicationResponse()).isEmpty();
  }

  @Test
  public void getSelectApplicationResponse_shouldSelectApplicationResponse() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getSelectApplicationResponse())
        .isEqualTo(selectApplicationResponse.getApdu());
  }

  @Test
  public void getDfName_shouldReturnDfNameFromFCI() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getDfName()).isEqualTo(ByteArrayUtil.fromHex(DF_NAME));
  }

  @Test
  public void getApplicationSerialNumber_shouldReturnApplicationSerialNumberFromFCI() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getApplicationSerialNumber())
        .isEqualTo(ByteArrayUtil.fromHex(CALYPSO_SERIAL_NUMBER));
  }

  @Test
  public void getStartupInfoRawData_shouldReturnFromFCI() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getStartupInfoRawData())
        .isEqualTo(ByteArrayUtil.fromHex(STARTUP_INFO_PRIME_REVISION_3));
  }

  @Test
  public void isPinFeatureAvailable_whenAppTypeBit0IsNotSet_shouldReturnFalse() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isPinFeatureAvailable()).isFalse();
  }

  @Test
  public void isPinFeatureAvailable_whenAppTypeBit0IsSet_shouldReturnTrue() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3_PIN, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isPinFeatureAvailable()).isTrue();
  }

  @Test
  public void isSvFeatureAvailable_whenAppTypeBit1IsNotSet_shouldReturnFalse() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isSvFeatureAvailable()).isFalse();
  }

  @Test
  public void isSvFeatureAvailable_whenAppTypeBit1IsSet_shouldReturnTrue() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3_STORED_VALUE, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isSvFeatureAvailable()).isTrue();
  }

  @Test
  public void isRatificationOnDeselectSupported_whenAppTypeBit2IsNotSet_shouldReturnTrue() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isRatificationOnDeselectSupported()).isTrue();
  }

  @Test
  public void isRatificationOnDeselectSupported_whenAppTypeBit2IsSet_shouldReturnFalse() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            STARTUP_INFO_PRIME_REVISION_3_RATIFICATION_ON_DESELECT,
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isRatificationOnDeselectSupported()).isFalse();
  }

  @Test
  public void isExtendedModeSupported_whenAppTypeBit3IsNotSet_shouldReturnFalse() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isExtendedModeSupported()).isFalse();
  }

  @Test
  public void isExtendedModeSupported_whenAppTypeBit3IsSet_shouldReturnTrue() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3_EXTENDED_MODE, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isExtendedModeSupported()).isTrue();
  }

  @Test
  public void isPkiModeSupported_whenAppTypeBit4IsNotSet_shouldReturnFalse() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isPkiModeSupported()).isFalse();
  }

  @Test
  public void isPkiModeSupported_whenAppTypeBit4IsSet_shouldReturnTrue() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_PRIME_REVISION_3_PKI_MODE, SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.isPkiModeSupported()).isTrue();
  }

  @Test
  public void getSessionModification_shouldReturnSessionModification() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            String.format(STARTUP_INFO_SESSION_MODIFICATION_XX, 0x11),
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getSessionModification()).isEqualTo((byte) 0x11);
  }

  @Test
  public void getPlatform_shouldReturnPlatformByte() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            String.format(STARTUP_INFO_PLATFORM_XX, 0x22),
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getPlatform()).isEqualTo((byte) 0x22);
  }

  @Test
  public void getApplicationType_shouldReturnApplicationType() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            String.format(STARTUP_INFO_APP_TYPE_XX, 0x33),
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getApplicationType()).isEqualTo((byte) 0x33);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getApplicationSubType_whenValueIs00_shouldThrowIAE() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            String.format(STARTUP_INFO_SUBTYPE_XX, 0x00),
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    calypsoCardAdapter.getApplicationSubtype();
  }

  @Test(expected = IllegalArgumentException.class)
  public void getApplicationSubType_whenValueIsFF_shouldThrowIAE() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            String.format(STARTUP_INFO_SUBTYPE_XX, 0xFF),
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    calypsoCardAdapter.getApplicationSubtype();
  }

  @Test
  public void getApplicationSubType_shouldReturnApplicationSubType() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            String.format(STARTUP_INFO_SUBTYPE_XX, 0x44),
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getApplicationSubtype()).isEqualTo((byte) 0x44);
  }

  @Test
  public void getSoftwareIssuer_shouldReturnSoftwareIssuer() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            String.format(STARTUP_INFO_SOFTWARE_ISSUER_XX, 0x55),
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getSoftwareIssuer()).isEqualTo((byte) 0x55);
  }

  @Test
  public void getSoftwareVersion_shouldReturnSoftwareVersion() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            String.format(STARTUP_INFO_SOFTWARE_VERSION_XX, 0x66),
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getSoftwareVersion()).isEqualTo((byte) 0x66);
  }

  @Test
  public void getSoftwareRevision_shouldReturnSoftwareRevision() {
    ApduResponseApi selectApplicationResponse =
        buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            String.format(STARTUP_INFO_SOFTWARE_REVISION_XX, 0x77),
            SW1SW2_OK);
    calypsoCardAdapter.initializeWithFci(selectApplicationResponse);
    assertThat(calypsoCardAdapter.getSoftwareRevision()).isEqualTo((byte) 0x77);
  }

  @Test(expected = IllegalStateException.class)
  public void getSvBalance_whenNotSet_shouldThrowISE() {
    calypsoCardAdapter.getSvBalance();
  }

  /**
   * (private)<br>
   * Builds a simulated response to a Select Application command.
   *
   * @param dfNameAsHexString The DF Name.
   * @param serialNumberAsHexString The Calypso Serial Number.
   * @param startupInfoAsHexString The startup info data.
   * @param statusWord The status word.
   * @return The APDU response containing the FCI and the status word.
   */
  private ApduResponseApi buildSelectApplicationResponse(
      String dfNameAsHexString,
      String serialNumberAsHexString,
      String startupInfoAsHexString,
      int statusWord) {

    byte[] dfName = ByteArrayUtil.fromHex(dfNameAsHexString);
    byte[] serialNumber = ByteArrayUtil.fromHex(serialNumberAsHexString);
    byte[] startupInfo = ByteArrayUtil.fromHex(startupInfoAsHexString);
    byte[] selAppResponse = new byte[23 + dfName.length + startupInfo.length];

    selAppResponse[0] = (byte) 0x6F;
    selAppResponse[1] = (byte) (11 + dfName.length + serialNumber.length + startupInfo.length);
    selAppResponse[2] = (byte) 0x84;
    selAppResponse[3] = (byte) (dfName.length);
    System.arraycopy(dfName, 0, selAppResponse, 4, dfName.length);
    selAppResponse[4 + dfName.length] = (byte) 0xA5;
    selAppResponse[5 + dfName.length] = (byte) (7 + serialNumber.length + startupInfo.length);
    selAppResponse[6 + dfName.length] = (byte) 0xBF;
    selAppResponse[7 + dfName.length] = (byte) 0x0C;
    selAppResponse[8 + dfName.length] = (byte) (4 + serialNumber.length + startupInfo.length);
    selAppResponse[9 + dfName.length] = (byte) 0xC7;
    selAppResponse[10 + dfName.length] = (byte) (serialNumber.length);
    System.arraycopy(serialNumber, 0, selAppResponse, 11 + dfName.length, 8);
    selAppResponse[19 + dfName.length] = (byte) 0x53;
    selAppResponse[20 + dfName.length] = (byte) (startupInfo.length);
    System.arraycopy(startupInfo, 0, selAppResponse, 21 + dfName.length, startupInfo.length);
    selAppResponse[21 + dfName.length + startupInfo.length] = (byte) ((statusWord & 0xFF00) >> 8);
    selAppResponse[22 + dfName.length + startupInfo.length] = (byte) (statusWord & 0xFF);
    return new ApduResponseAdapter(selAppResponse);
  }
}
