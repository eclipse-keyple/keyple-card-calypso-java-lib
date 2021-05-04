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
package Demo_CalypsoClassic;

import org.eclipse.keyple.card.calypso.CalypsoExtensionService;
import org.eclipse.keyple.card.calypso.sam.CalypsoSamResourceProfileExtension;
import org.eclipse.keyple.card.calypso.sam.SamRevision;
import org.eclipse.keyple.core.service.Plugin;
import org.eclipse.keyple.core.service.Reader;
import org.eclipse.keyple.core.service.resource.CardResourceProfileConfigurator;
import org.eclipse.keyple.core.service.resource.CardResourceService;
import org.eclipse.keyple.core.service.resource.CardResourceServiceProvider;
import org.eclipse.keyple.core.service.resource.PluginsConfigurator;
import org.eclipse.keyple.core.service.resource.spi.ReaderConfiguratorSpi;
import org.eclipse.keyple.core.service.spi.PluginObservationExceptionHandlerSpi;
import org.eclipse.keyple.core.service.spi.ReaderObservationExceptionHandlerSpi;
import org.eclipse.keyple.plugin.pcsc.PcscReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class SamResourceService
    implements ReaderConfiguratorSpi,
        PluginObservationExceptionHandlerSpi,
        ReaderObservationExceptionHandlerSpi {

  private static final Logger logger = LoggerFactory.getLogger(SamResourceService.class);
  private final CardResourceService cardResourceService;

  /**
   * Create card resource service dedicated to SAM resource allocations.
   *
   * @param plugin The plugin in which SAM readers are available.
   * @param cardExtension The card extension.
   */
  SamResourceService(Plugin plugin, CalypsoExtensionService cardExtension) {

    CalypsoSamResourceProfileExtension samCardResourceExtension =
        cardExtension
            .createSamResourceProfileExtension()
            .setSamRevision(SamRevision.C1)
            .setSamUnlockData("00112233445566778899AABBCCDDEEFF");

    cardResourceService = CardResourceServiceProvider.getService();

    cardResourceService
        .getConfigurator()
        .withPlugins(
            PluginsConfigurator.builder().addPluginWithMonitoring(plugin, this, this, this).build())
        .withCardResourceProfiles(
            CardResourceProfileConfigurator.builder("SAM C1", samCardResourceExtension)
                .withReaderNameRegex(".*Identive.*|.*HID.*")
                .build())
        .configure();
  }

  /** Starts the card resource service. */
  void start() {
    cardResourceService.start();
  }

  /** Stops the card resource service. */
  void stop() {
    cardResourceService.stop();
  }

  /**
   * {@inheritDoc}<br>
   * Sets up the provided PC/SC reader
   *
   * @param reader A PC/SC reader.
   */
  @Override
  public void setupReader(Reader reader) {

    // Configure the reader with parameters suitable for contactless operations.
    try {
      reader
          .getExtension(PcscReader.class)
          .setContactless(false)
          .setIsoProtocol(PcscReader.IsoProtocol.T0)
          .setSharingMode(PcscReader.SharingMode.SHARED);
    } catch (Exception e) {
      logger.error("Exception raised while setting up the reader {}", reader.getName(), e);
    }
  }

  @Override
  public void onPluginObservationError(String pluginName, Throwable e) {
    logger.error("Plugin observation exception: {}", e.getMessage(), e);
  }

  @Override
  public void onReaderObservationError(String pluginName, String readerName, Throwable e) {
    logger.error("Reader observation exception: {}", e.getMessage(), e);
  }
}
