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

import org.eclipse.keyple.core.common.CommonApiProperties;
import org.eclipse.keypop.calypso.card.transaction.FreeTransactionManager;
import org.eclipse.keypop.calypso.card.transaction.SymmetricCryptoSecuritySetting;
import org.eclipse.keypop.calypso.card.transaction.spi.CardTransactionCryptoExtension;
import org.eclipse.keypop.calypso.card.transaction.spi.SymmetricCryptoTransactionManagerFactory;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoTransactionManagerFactorySpi;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoTransactionManagerSpi;
import org.eclipse.keypop.card.CardApiProperties;
import org.eclipse.keypop.card.ProxyReaderApi;
import org.eclipse.keypop.card.spi.CardSelectionExtensionSpi;
import org.eclipse.keypop.reader.CardReader;
import org.eclipse.keypop.reader.ReaderApiProperties;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class CalypsoExtensionServiceTest {

  public static final String POWER_ON_DATA = "3B8F8001805A0A010320031124B77FE7829000F7";
  private static final String SAM_C1_POWER_ON_DATA = "3B3F9600805A4880C120501711223344829000";
  private static CalypsoExtensionService service;
  private ReaderMock reader;
  private CalypsoCardAdapter calypsoCard;
  private SymmetricCryptoSecuritySetting cardSecuritySetting;
  private SymmetricCryptoTransactionManagerFactoryMock symmetricCryptoTransactionManagerFactory;
  private SymmetricCryptoTransactionManagerMock symmetricCryptoTransactionManager;

  interface ReaderMock extends CardReader, ProxyReaderApi {}

  interface SymmetricCryptoTransactionManagerFactoryMock
      extends SymmetricCryptoTransactionManagerFactory,
          SymmetricCryptoTransactionManagerFactorySpi {}

  interface SymmetricCryptoTransactionManagerMock
      extends SymmetricCryptoTransactionManagerSpi, CardTransactionCryptoExtension {}

  @BeforeClass
  public static void beforeClass() {
    service = CalypsoExtensionService.getInstance();
  }

  @Before
  public void setUp() throws Exception {
    reader = mock(ReaderMock.class);
    symmetricCryptoTransactionManagerFactory =
        mock(SymmetricCryptoTransactionManagerFactoryMock.class);
    symmetricCryptoTransactionManager = mock(SymmetricCryptoTransactionManagerMock.class);
    calypsoCard = new CalypsoCardAdapter(null);
    cardSecuritySetting = mock(SymmetricCryptoSecuritySettingAdapter.class);
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
    assertThat(service.getCalypsoCardApiFactory().createSearchCommandData())
        .isNotNull()
        .isNotEqualTo(service.getCalypsoCardApiFactory().createSearchCommandData());
  }

  @Test
  public void createCardSelection_shouldReturnNewReference() {
    assertThat(service.getCalypsoCardApiFactory().createCalypsoCardSelectionExtension())
        .isNotNull()
        .isNotEqualTo(service.getCalypsoCardApiFactory().createCalypsoCardSelectionExtension());
  }

  @Test
  public void createCardSelection_shouldReturnInstanceOfInternalSpi() {
    assertThat(service.getCalypsoCardApiFactory().createCalypsoCardSelectionExtension())
        .isInstanceOf(CardSelectionExtensionSpi.class)
        .isInstanceOf(CalypsoCardSelectionExtensionAdapter.class);
  }

  @Test
  public void createCardSecuritySetting_shouldReturnANewReference() {
    SymmetricCryptoSecuritySetting cardSecuritySetting =
        service
            .getCalypsoCardApiFactory()
            .createSymmetricCryptoSecuritySetting(symmetricCryptoTransactionManagerFactory);
    assertThat(cardSecuritySetting).isNotNull();
    assertThat(
            service
                .getCalypsoCardApiFactory()
                .createSymmetricCryptoSecuritySetting(symmetricCryptoTransactionManagerFactory))
        .isNotEqualTo(cardSecuritySetting);
  }

  @Test
  public void createCardSecuritySetting_shouldReturnInstanceOfCardSecuritySettingAdapter() {
    assertThat(
            service
                .getCalypsoCardApiFactory()
                .createSymmetricCryptoSecuritySetting(symmetricCryptoTransactionManagerFactory))
        .isInstanceOf(SymmetricCryptoSecuritySettingAdapter.class);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createFreeTransactionManager_whenInvokedWithNullReader_shouldThrowIAE() {
    service.getCalypsoCardApiFactory().createFreeTransactionManager(null, calypsoCard);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createFreeTransactionManager_whenInvokedWithNullCalypsoCard_shouldThrowIAE() {
    service.getCalypsoCardApiFactory().createFreeTransactionManager(reader, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      createFreeTransactionManager_whenInvokedWithUndefinedCalypsoCardProductType_shouldThrowIAE() {
    service.getCalypsoCardApiFactory().createFreeTransactionManager(reader, calypsoCard);
  }

  @Test
  public void createFreeTransactionManager_whenInvoked_shouldReturnANewReference()
      throws Exception {
    calypsoCard = new CalypsoCardAdapter(new CardSelectionResponseAdapter(POWER_ON_DATA));
    FreeTransactionManager cardTransaction =
        service.getCalypsoCardApiFactory().createFreeTransactionManager(reader, calypsoCard);
    assertThat(service.getCalypsoCardApiFactory().createFreeTransactionManager(reader, calypsoCard))
        .isNotEqualTo(cardTransaction);
  }

  @Test(expected = IllegalArgumentException.class)
  public void createSecureRegularModeTransactionManager_whenInvokedWithNullReader_shouldThrowIAE() {
    service
        .getCalypsoCardApiFactory()
        .createSecureRegularModeTransactionManager(null, calypsoCard, cardSecuritySetting);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      createSecureRegularModeTransactionManager_whenInvokedWithNullCalypsoCard_shouldThrowIAE() {
    service
        .getCalypsoCardApiFactory()
        .createSecureRegularModeTransactionManager(reader, null, cardSecuritySetting);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      createSecureRegularModeTransactionManager_whenInvokedWithNullCardSecuritySetting_shouldThrowIAE() {
    service
        .getCalypsoCardApiFactory()
        .createSecureRegularModeTransactionManager(reader, calypsoCard, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      createSecureRegularModeTransactionManager_whenInvokedWithUndefinedCalypsoCardProductType_shouldThrowIAE() {
    service
        .getCalypsoCardApiFactory()
        .createSecureRegularModeTransactionManager(reader, calypsoCard, cardSecuritySetting);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      createSecureExtendedModeTransactionManager_whenInvokedWithNullReader_shouldThrowIAE() {
    service
        .getCalypsoCardApiFactory()
        .createSecureExtendedModeTransactionManager(null, calypsoCard, cardSecuritySetting);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      createSecureExtendedModeTransactionManager_whenInvokedWithNullCalypsoCard_shouldThrowIAE() {
    service
        .getCalypsoCardApiFactory()
        .createSecureExtendedModeTransactionManager(reader, null, cardSecuritySetting);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      createSecureExtendedModeTransactionManager_whenInvokedWithNullCardSecuritySetting_shouldThrowIAE() {
    service
        .getCalypsoCardApiFactory()
        .createSecureExtendedModeTransactionManager(reader, calypsoCard, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      createSecureExtendedModeTransactionManager_whenInvokedWithUndefinedCalypsoCardProductType_shouldThrowIAE() {
    service
        .getCalypsoCardApiFactory()
        .createSecureExtendedModeTransactionManager(reader, calypsoCard, cardSecuritySetting);
  }
}
