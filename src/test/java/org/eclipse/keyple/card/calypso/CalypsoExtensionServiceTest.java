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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.calypsonet.terminal.calypso.card.CalypsoCardSelection;
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.sam.CalypsoSamSelection;
import org.calypsonet.terminal.calypso.transaction.CardSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.CardTransactionManager;
import org.calypsonet.terminal.card.CardApiProperties;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.calypsonet.terminal.card.spi.CardSelectionSpi;
import org.calypsonet.terminal.reader.CardReader;
import org.calypsonet.terminal.reader.ReaderApiProperties;
import org.eclipse.keyple.core.common.CommonApiProperties;
import org.eclipse.keyple.core.service.resource.spi.CardResourceProfileExtension;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class CalypsoExtensionServiceTest {

  public static final String POWER_ON_DATA = "3B8F8001805A0A010320031124B77FE7829000F7";
  private static CalypsoExtensionService service;
  private CalypsoSamSelection calypsoSamSelection;
  private ReaderMock reader;
  private CalypsoCardAdapter calypsoCard;
  private CalypsoSam calypsoSam;
  private CardSecuritySetting cardSecuritySetting;

  interface ReaderMock extends CardReader, ProxyReaderApi {}

  @BeforeClass
  public static void beforeClass() {
    service = CalypsoExtensionService.getInstance();
  }

  @Before
  public void setUp() {
    reader = mock(ReaderMock.class);
    calypsoCard = new CalypsoCardAdapter();
    calypsoSam = mock(CalypsoSam.class);
    calypsoSamSelection = mock(CalypsoSamSelection.class);
    cardSecuritySetting = mock(CardSecuritySettingAdapter.class);
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
  public void createCardSelection_shouldReturnNewReference() {
    CalypsoCardSelection cardSelection = service.createCardSelection();
    assertThat(cardSelection).isNotNull();
    assertThat(service.createCardSelection()).isNotEqualTo(cardSelection);
  }

  @Test
  public void createCardSelection_shouldReturnInstanceOfInternalSpi() {
    assertThat(service.createCardSelection())
        .isInstanceOf(CardSelectionSpi.class)
        .isInstanceOf(CalypsoCardSelectionAdapter.class);
  }

  @Test
  public void createSamSelection_shouldReturnNewReference() {
    CalypsoSamSelection samSelection = service.createSamSelection();
    assertThat(samSelection).isNotNull();
    assertThat(service.createSamSelection()).isNotEqualTo(samSelection);
  }

  @Test
  public void createSamSelection_shouldReturnInstanceOfInternalSpi() {
    assertThat(service.createSamSelection())
        .isInstanceOf(CardSelectionSpi.class)
        .isInstanceOf(CalypsoSamSelectionAdapter.class);
  }

  @Test
  public void createSamResourceProfileExtension_shouldReturnANewReference() {
    CardResourceProfileExtension samResourceProfileExtension =
        service.createSamResourceProfileExtension(calypsoSamSelection);
    assertThat(samResourceProfileExtension).isNotNull();
    assertThat(service.createSamResourceProfileExtension(calypsoSamSelection))
        .isNotEqualTo(samResourceProfileExtension);
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

  @Test
  public void createCardTransaction_shouldReturnANewReference() {
    calypsoCard.initializeWithPowerOnData(POWER_ON_DATA);
    when(((CardSecuritySettingAdapter) cardSecuritySetting).getCalypsoSam()).thenReturn(calypsoSam);
    when(((CardSecuritySettingAdapter) cardSecuritySetting).getSamReader()).thenReturn(reader);
    CardTransactionManager cardTransaction =
        service.createCardTransaction(reader, calypsoCard, cardSecuritySetting);
    assertThat(service.createCardTransaction(reader, calypsoCard, cardSecuritySetting))
        .isNotEqualTo(cardTransaction);
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
  public void createCardTransactionWithoutSecurity_whenInvoked_shouldReturnANewReference() {
    calypsoCard.initializeWithPowerOnData(POWER_ON_DATA);
    when(((CardSecuritySettingAdapter) cardSecuritySetting).getCalypsoSam()).thenReturn(calypsoSam);
    when(((CardSecuritySettingAdapter) cardSecuritySetting).getSamReader()).thenReturn(reader);
    CardTransactionManager cardTransaction =
        service.createCardTransactionWithoutSecurity(reader, calypsoCard);
    assertThat(service.createCardTransactionWithoutSecurity(reader, calypsoCard))
        .isNotEqualTo(cardTransaction);
  }
}
