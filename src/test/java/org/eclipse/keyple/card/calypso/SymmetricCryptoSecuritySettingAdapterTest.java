/* **************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/
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

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.when;

import org.eclipse.keypop.calypso.card.transaction.SymmetricCryptoSecuritySetting;
import org.eclipse.keypop.calypso.card.transaction.spi.SymmetricCryptoCardTransactionManagerFactory;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoCardTransactionManagerFactorySpi;
import org.junit.Before;
import org.junit.Test;

public class SymmetricCryptoSecuritySettingAdapterTest {

  private SymmetricCryptoSecuritySetting cardSecuritySetting;
  private SymmetricCryptoCardTransactionManagerFactoryMock
      symmetricCryptoCardTransactionManagerFactory;

  interface SymmetricCryptoCardTransactionManagerFactoryMock
      extends SymmetricCryptoCardTransactionManagerFactory,
          SymmetricCryptoCardTransactionManagerFactorySpi {}

  @Before
  public void setUp() throws Exception {
    // Mock crypto factory
    symmetricCryptoCardTransactionManagerFactory =
        mock(SymmetricCryptoCardTransactionManagerFactoryMock.class);
    when(symmetricCryptoCardTransactionManagerFactory.getMaxCardApduLengthSupported())
        .thenReturn(250);
    when(symmetricCryptoCardTransactionManagerFactory.isExtendedModeSupported()).thenReturn(true);

    // Mock security setting
    cardSecuritySetting =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSymmetricCryptoSecuritySetting(symmetricCryptoCardTransactionManagerFactory);
  }

  @Test
  public void initCryptoContextForNextTransaction_shouldRequestCryptoModule() throws Exception {

    cardSecuritySetting.initCryptoContextForNextTransaction();

    verify(symmetricCryptoCardTransactionManagerFactory).preInitTerminalSessionContext();
    verifyNoMoreInteractions(symmetricCryptoCardTransactionManagerFactory);
  }
}
