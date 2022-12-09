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

import java.util.List;
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.card.ProxyReaderApi;

/**
 * Adapter of {@link SymmetricCryptoTransactionManagerFactory} and {@link
 * SymmetricCryptoTransactionManagerFactorySpi}.
 *
 * @since 2.3.1
 */
class SymmetricCryptoTransactionManagerFactoryAdapter
    implements SymmetricCryptoTransactionManagerFactory,
        SymmetricCryptoTransactionManagerFactorySpi {

  private final ProxyReaderApi samReader;
  private final CalypsoSamAdapter sam;
  private final boolean isExtendedModeSupported;
  private final int maxCardApduLengthSupported;
  // Temporary field for manage PSO signature
  private final CardSecuritySettingAdapter tmpCardSecuritySetting;

  SymmetricCryptoTransactionManagerFactoryAdapter(
      ProxyReaderApi samReader,
      CalypsoSamAdapter sam,
      Integer contactReaderPayloadCapacity,
      CardSecuritySettingAdapter tmpCardSecuritySetting) {
    this.samReader = samReader;
    this.sam = sam;
    this.tmpCardSecuritySetting = tmpCardSecuritySetting;
    this.isExtendedModeSupported =
        sam.getProductType() == CalypsoSam.ProductType.SAM_C1
            || sam.getProductType() == CalypsoSam.ProductType.HSM_C1;
    this.maxCardApduLengthSupported =
        contactReaderPayloadCapacity != null
            ? Math.min(sam.getMaxDigestDataLength(), contactReaderPayloadCapacity)
            : sam.getMaxDigestDataLength();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public boolean isExtendedModeSupported() {
    return isExtendedModeSupported;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public int getMaxCardApduLengthSupported() {
    return maxCardApduLengthSupported;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoTransactionManagerAdapter createTransactionManager(
      byte[] cardKeyDiversifier, boolean useExtendedMode, List<byte[]> transactionAuditData) {
    if (useExtendedMode && !isExtendedModeSupported) {
      throw new IllegalStateException("The extended mode is not supported by the crypto service");
    }
    return new SymmetricCryptoTransactionManagerAdapter(
        samReader,
        sam,
        cardKeyDiversifier,
        useExtendedMode,
        maxCardApduLengthSupported,
        transactionAuditData,
        tmpCardSecuritySetting);
  }
}
