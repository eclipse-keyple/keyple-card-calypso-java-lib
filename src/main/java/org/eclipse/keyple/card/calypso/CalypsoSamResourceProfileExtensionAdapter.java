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

import org.calypsonet.terminal.calypso.sam.CalypsoSamSelection;
import org.calypsonet.terminal.reader.CardReader;
import org.calypsonet.terminal.reader.selection.CardSelectionManager;
import org.calypsonet.terminal.reader.selection.CardSelectionResult;
import org.calypsonet.terminal.reader.selection.spi.SmartCard;
import org.eclipse.keyple.core.service.resource.spi.CardResourceProfileExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Implementation of {@link CardResourceProfileExtension} dedicated to SAM identification.
 *
 * @since 2.0
 */
class CalypsoSamResourceProfileExtensionAdapter implements CardResourceProfileExtension {
  private static final Logger logger =
      LoggerFactory.getLogger(CalypsoSamResourceProfileExtensionAdapter.class);
  private final CalypsoSamSelection calypsoSamSelection;

  /**
   * (package-private)<br>
   *
   * @param calypsoSamSelection The {@link CalypsoSamSelection}.
   * @since 2.0
   */
  CalypsoSamResourceProfileExtensionAdapter(CalypsoSamSelection calypsoSamSelection) {
    this.calypsoSamSelection = calypsoSamSelection;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SmartCard matches(CardReader reader, CardSelectionManager samCardSelectionManager) {

    if (!reader.isCardPresent()) {
      return null;
    }

    samCardSelectionManager.prepareSelection(calypsoSamSelection);
    CardSelectionResult samCardSelectionResult = null;
    try {
      samCardSelectionResult = samCardSelectionManager.processCardSelectionScenario(reader);
    } catch (Exception e) {
      logger.warn("An exception occurred while selecting the SAM: '{}'.", e.getMessage(), e);
    }

    if (samCardSelectionResult != null) {
      return samCardSelectionResult.getActiveSmartCard();
    }

    return null;
  }
}
