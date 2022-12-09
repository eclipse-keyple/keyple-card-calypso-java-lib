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

import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.spi.SamRevocationServiceSpi;
import org.calypsonet.terminal.calypso.transaction.CommonSecuritySetting;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.calypsonet.terminal.reader.CardReader;
import org.eclipse.keyple.core.util.Assert;

/**
 * Implementation of {@link CommonSecuritySetting}.
 *
 * @param <S> The type of the lowest level child object.
 * @since 2.2.0
 */
abstract class CommonSecuritySettingAdapter<S extends CommonSecuritySetting<S>>
    implements CommonSecuritySetting<S> {

  private final S currentInstance = (S) this;
  private ProxyReaderApi controlSamReader;
  private CalypsoSamAdapter controlSam;
  private SamRevocationServiceSpi samRevocationServiceSpi;

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public final S setControlSamResource(CardReader samReader, CalypsoSam calypsoSam) {

    Assert.getInstance()
        .notNull(samReader, "samReader")
        .notNull(calypsoSam, "calypsoSam")
        .notNull(calypsoSam.getProductType(), "productType")
        .isTrue(calypsoSam.getProductType() != CalypsoSam.ProductType.UNKNOWN, "productType");

    if (!(samReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
          "The provided 'samReader' must implement 'ProxyReaderApi'");
    }
    if (!(calypsoSam instanceof CalypsoSamAdapter)) {
      throw new IllegalArgumentException(
          "The provided 'calypsoSam' must be an instance of 'CalypsoSamAdapter'");
    }

    this.controlSamReader = (ProxyReaderApi) samReader;
    this.controlSam = (CalypsoSamAdapter) calypsoSam;

    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public final S setSamRevocationService(SamRevocationServiceSpi service) {
    Assert.getInstance().notNull(service, "service");
    this.samRevocationServiceSpi = service;
    return currentInstance;
  }

  /**
   * Gets the associated control SAM reader to use for secured operations.
   *
   * @return Null if no control SAM reader is set.
   * @since 2.2.0
   */
  final ProxyReaderApi getControlSamReader() {
    return controlSamReader;
  }

  /**
   * Gets the control SAM used for secured operations.
   *
   * @return Null if no control SAM is set.
   * @since 2.2.0
   */
  final CalypsoSamAdapter getControlSam() {
    return controlSam;
  }

  /**
   * Gets the SAM revocation service.
   *
   * @return Null if no SAM revocation service is set.
   * @since 2.2.0
   */
  final SamRevocationServiceSpi getSamRevocationServiceSpi() {
    return samRevocationServiceSpi;
  }
}
