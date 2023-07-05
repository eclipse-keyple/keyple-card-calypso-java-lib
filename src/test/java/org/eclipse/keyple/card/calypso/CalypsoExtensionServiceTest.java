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
import static org.eclipse.keyple.card.calypso.TestDtoAdapters.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.sam.CalypsoSamSelection;
import org.calypsonet.terminal.calypso.transaction.CardSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.CardTransactionManager;
import org.calypsonet.terminal.calypso.transaction.SamSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.SamTransactionManager;
import org.calypsonet.terminal.card.CardApiProperties;
import org.calypsonet.terminal.card.CardSelectionResponseApi;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.calypsonet.terminal.card.spi.CardSelectionSpi;
import org.calypsonet.terminal.reader.CardReader;
import org.calypsonet.terminal.reader.ReaderApiProperties;
import org.eclipse.keyple.core.common.CommonApiProperties;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class CalypsoExtensionServiceTest {

  public static final String POWER_ON_DATA = "3B8F8001805A0A010320031124B77FE7829000F7";
  private static final String SAM_C1_POWER_ON_DATA = "3B3F9600805A4880C120501711223344829000";
  private static CalypsoExtensionService service;
  private CalypsoSamSelection calypsoSamSelection;
  private ReaderMock reader;
  private CalypsoCardAdapter calypsoCard;
  private CardSecuritySetting cardSecuritySetting;
  private CalypsoSamAdapter calypsoSam;
  private SamSecuritySetting samSecuritySetting;

  interface ReaderMock extends CardReader, ProxyReaderApi {}

  @BeforeClass
  public static void beforeClass() {
    service = CalypsoExtensionService.getInstance();
  }

  @Before
  public void setUp() throws Exception {
    reader = mock(ReaderMock.class);

    calypsoCard = new CalypsoCardAdapter(null);
    cardSecuritySetting = mock(CardSecuritySettingAdapter.class);

    calypsoSamSelection = mock(CalypsoSamSelection.class);
    CardSelectionResponseApi samCardSelectionResponse = mock(CardSelectionResponseApi.class);
    when(samCardSelectionResponse.getPowerOnData()).thenReturn(SAM_C1_POWER_ON_DATA);
    calypsoSam = spy(new CalypsoSamAdapter(samCardSelectionResponse));
    samSecuritySetting = mock(SamSecuritySettingAdapter.class);
  }

  @Test
  public void getInstance_whenIsInvokedTwice_shouldReturnSameInstance() {
    assertThat(CalypsoExtensionService.getInstance()).isEqualTo(service);
  }

  @Test
  public void getReaderApiVersion_whenInvoked_shouldReturn_ExpectedVersion() {
    assertThat(service.getReaderApiVersion()).isEqualTo(ReaderApiProperties.VERSION);
  }

  @Test
  public void getCardApiVersion_shouldReturnExpectedVersion() {
    assertThat(service.getCardApiVersion()).isEqualTo(CardApiProperties.VERSION);
  }

  @Test
  public void getCommonApiVersion_shouldReturnExpectedVersion() {
    assertThat(service.getCommonApiVersion()).isEqualTo(CommonApiProperties.VERSION);
  }

  @Test
  public void createSearchCommandData_shouldReturnNewReference() {
    assertThat(service.createSearchCommandData())
        .isNotNull()
        .isNotEqualTo(service.createSearchCommandData());
  }

  @Test
  public void createBasicSignatureComputationData_shouldReturnNewReference() {
    assertThat(service.createBasicSignatureComputationData())
        .isNotNull()
        .isNotEqualTo(service.createBasicSignatureComputationData());
  }

  @Test
  public void createTraceableSignatureComputationData_shouldReturnNewReference() {
    assertThat(service.createTraceableSignatureComputationData())
        .isNotNull()
        .isNotEqualTo(service.createTraceableSignatureComputationData());
  }

  @Test
  public void createBasicSignatureVerificationData_shouldReturnNewReference() {
    assertThat(service.createBasicSignatureVerificationData())
        .isNotNull()
        .isNotEqualTo(service.createBasicSignatureVerificationData());
  }

  @Test
  public void createTraceableSignatureVerificationData_shouldReturnNewReference() {
    assertThat(service.createTraceableSignatureVerificationData())
        .isNotNull()
        .isNotEqualTo(service.createTraceableSignatureVerificationData());
  }

  @Test
  public void createCardSelection_shouldReturnNewReference() {
    assertThat(service.createCardSelection())
        .isNotNull()
        .isNotEqualTo(service.createCardSelection());
  }

  @Test
  public void createCardSelection_shouldReturnInstanceOfInternalSpi() {
    assertThat(service.createCardSelection())
        .isInstanceOf(CardSelectionSpi.class)
        .isInstanceOf(CalypsoCardSelectionAdapter.class);
  }

  @Test
  public void createSamSelection_shouldReturnNewReference() {
    //
    // assertThat(service.createSamSelection()).isNotNull().isNotEqualTo(service.createSamSelection());
  }

  @Test
  public void createSamSelection_shouldReturnInstanceOfInternalSpi() {
    //    assertThat(service.createSamSelection())
    //        .isInstanceOf(CardSelectionSpi.class)
    //        .isInstanceOf(CalypsoSamSelectionAdapter.class);
  }

  @Test
  public void createSamResourceProfileExtension_shouldReturnANewReference() {
    //    CardResourceProfileExtension samResourceProfileExtension =
    //        service.createSamResourceProfileExtension(calypsoSamSelection);
    //    assertThat(samResourceProfileExtension).isNotNull();
    //    assertThat(service.createSamResourceProfileExtension(calypsoSamSelection))
    //        .isNotEqualTo(samResourceProfileExtension);
  }

  @Test
  public void createCardSecuritySetting_shouldReturnANewReference() {
    CardSecuritySetting cardSecuritySetting = service.createCardSecuritySetting();
    assertThat(cardSecuritySetting).isNotNull();
    assertThat(service.createCardSecuritySetting()).isNotEqualTo(cardSecuritySetting);
  }

  @Test
  public void createCardSecuritySetting_shouldReturnInstanceOfCardSecuritySettingAdapter() {
    assertThat(service.createCardSecuritySetting()).isInstanceOf(CardSecuritySettingAdapter.class);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createCardTransaction_whenInvokedWithNullReader_shouldThrowIAE() {
    service.createCardTransaction(null, calypsoCard, cardSecuritySetting);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createCardTransaction_whenInvokedWithNullCalypsoCard_shouldThrowIAE() {
    service.createCardTransaction(reader, null, cardSecuritySetting);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createCardTransaction_whenInvokedWithNullCardSecuritySetting_shouldThrowIAE() {
    service.createCardTransaction(reader, calypsoCard, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      createCardTransaction_whenInvokedWithUndefinedCalypsoCardProductType_shouldThrowIAE() {
    service.createCardTransaction(reader, calypsoCard, cardSecuritySetting);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createCardTransactionWithoutSecurity_whenInvokedWithNullReader_shouldThrowIAE() {
    service.createCardTransactionWithoutSecurity(null, calypsoCard);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createCardTransactionWithoutSecurity_whenInvokedWithNullCalypsoCard_shouldThrowIAE() {
    service.createCardTransactionWithoutSecurity(reader, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      createCardTransactionWithoutSecurity_whenInvokedWithUndefinedCalypsoCardProductType_shouldThrowIAE() {
    service.createCardTransactionWithoutSecurity(reader, calypsoCard);
  }

  @Test
  public void createCardTransactionWithoutSecurity_whenInvoked_shouldReturnANewReference()
      throws Exception {
    calypsoCard = new CalypsoCardAdapter(new CardSelectionResponseAdapter(POWER_ON_DATA));
    CardTransactionManager cardTransaction =
        service.createCardTransactionWithoutSecurity(reader, calypsoCard);
    assertThat(service.createCardTransactionWithoutSecurity(reader, calypsoCard))
        .isNotEqualTo(cardTransaction);
  }

  @Test
  public void createSamSecuritySetting_shouldReturnANewReference() {
    SamSecuritySetting samSecuritySetting = service.createSamSecuritySetting();
    assertThat(samSecuritySetting).isNotNull();
    assertThat(service.createSamSecuritySetting()).isNotEqualTo(samSecuritySetting);
  }

  @Test
  public void createSamSecuritySetting_shouldReturnInstanceOfSamSecuritySettingAdapter() {
    assertThat(service.createSamSecuritySetting()).isInstanceOf(SamSecuritySettingAdapter.class);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createSamTransaction_whenInvokedWithNullReader_shouldThrowIAE() {
    service.createSamTransaction(null, calypsoSam, samSecuritySetting);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createSamTransaction_whenInvokedWithNullCalypsoCard_shouldThrowIAE() {
    service.createSamTransaction(reader, null, samSecuritySetting);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createSamTransaction_whenInvokedWithNullSamSecuritySetting_shouldThrowIAE() {
    service.createSamTransaction(reader, calypsoSam, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createSamTransaction_whenInvokedWithUndefinedCalypsoSamProductType_shouldThrowIAE() {
    when(calypsoSam.getProductType()).thenReturn(CalypsoSam.ProductType.UNKNOWN);
    service.createSamTransaction(reader, calypsoSam, samSecuritySetting);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createSamTransactionWithoutSecurity_whenInvokedWithNullReader_shouldThrowIAE() {
    service.createSamTransactionWithoutSecurity(null, calypsoSam);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createSamTransactionWithoutSecurity_whenInvokedWithNullCalypsoSam_shouldThrowIAE() {
    service.createSamTransactionWithoutSecurity(reader, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      createSamTransactionWithoutSecurity_whenInvokedWithUndefinedCalypsoSamProductType_shouldThrowIAE() {
    when(calypsoSam.getProductType()).thenReturn(CalypsoSam.ProductType.UNKNOWN);
    service.createSamTransactionWithoutSecurity(reader, calypsoSam);
  }

  @Test
  public void createSamTransactionWithoutSecurity_whenInvoked_shouldReturnANewReference() {
    SamTransactionManager samTransaction =
        service.createSamTransactionWithoutSecurity(reader, calypsoSam);
    assertThat(service.createSamTransactionWithoutSecurity(reader, calypsoSam))
        .isNotEqualTo(samTransaction);
  }
}
