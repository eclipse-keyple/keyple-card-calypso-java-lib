/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.calypso;

import org.eclipse.keyple.calypso.sam.SamCardResourceProfileExtension;
import org.eclipse.keyple.calypso.sam.SamRevision;
import org.eclipse.keyple.core.card.ProxyReader;
import org.eclipse.keyple.core.card.spi.CardResourceProfileExtensionSpi;
import org.eclipse.keyple.core.card.spi.SmartCardSpi;
import org.eclipse.keyple.core.service.CardSelectionServiceFactory;
import org.eclipse.keyple.core.service.Reader;
import org.eclipse.keyple.core.service.selection.CardSelectionResult;
import org.eclipse.keyple.core.service.selection.CardSelectionService;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * Implementation of {@link SamCardResourceProfileExtension}.
 *
 * @since 2.0
 */
public class SamCardResourceProfileExtensionAdapter
    implements SamCardResourceProfileExtension, CardResourceProfileExtensionSpi {

  private SamRevision samRevision;
  private String samSerialNumberRegex;
  private String samUnlockData;

  /**
   * (package-private)<br>
   *
   * @since 2.0
   */
  SamCardResourceProfileExtensionAdapter() {}

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamCardResourceProfileExtension setSamRevision(SamRevision samRevision) {
    this.samRevision = samRevision;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamCardResourceProfileExtension setSamSerialNumberRegex(String samSerialNumberRegex) {
    this.samSerialNumberRegex = samSerialNumberRegex;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamCardResourceProfileExtension setSamUnlockData(String samUnlockData) {
    this.samUnlockData = samUnlockData;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SmartCardSpi matches(ProxyReader reader) {

    if (!((Reader) reader).isCardPresent()) {
      return null;
    }

    CalypsoSamCardSelector calypsoSamCardSelector =
        CalypsoSamCardSelector.builder()
            .setTargetSamRevision(samRevision)
            .setSerialNumber(samSerialNumberRegex)
            .setUnlockData(ByteArrayUtil.fromHex(samUnlockData))
            .build();

    CardSelectionService samSelectionService = CardSelectionServiceFactory.getService();

    CalypsoSamCardSelectionAdapter calypsoSamCardSelectionAdapter =
        new CalypsoSamCardSelectionAdapter(calypsoSamCardSelector);

    samSelectionService.prepareSelection(calypsoSamCardSelectionAdapter);

    CardSelectionResult samCardSelectionResult =
        samSelectionService.processCardSelectionScenario((Reader) reader);

    return (SmartCardSpi) samCardSelectionResult.getActiveSmartCard();
  }
}
