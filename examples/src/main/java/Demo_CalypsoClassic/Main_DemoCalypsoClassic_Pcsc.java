/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://www.calypsonet-asso.org/
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

import static common.ConfigurationUtils.getCardReader;

import common.CalypsoDef;
import org.eclipse.keyple.card.calypso.CalypsoExtensionService;
import org.eclipse.keyple.card.calypso.CalypsoExtensionServiceProvider;
import org.eclipse.keyple.core.service.*;
import org.eclipse.keyple.core.service.resource.CardResourceServiceProvider;
import org.eclipse.keyple.core.service.selection.CardSelectionService;
import org.eclipse.keyple.core.service.selection.CardSelector;
import org.eclipse.keyple.plugin.pcsc.PcscPluginFactoryBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main_DemoCalypsoClassic_Pcsc {
  private static final Logger logger = LoggerFactory.getLogger(Main_DemoCalypsoClassic_Pcsc.class);

  public static void main(String[] args) throws Exception {

    // Get the instance of the SmartCardService (singleton pattern)
    SmartCardService smartCardService = SmartCardServiceProvider.getService();

    // Register the PcscPlugin with the SmartCardService, get the corresponding generic plugin in
    // return.
    Plugin plugin = smartCardService.registerPlugin(PcscPluginFactoryBuilder.builder().build());

    // Get the Calypso card extension service
    CalypsoExtensionService cardExtension = CalypsoExtensionServiceProvider.getService();

    // Verify that the extension's API level is consistent with the current service.
    smartCardService.checkCardExtension(cardExtension);

    Reader cardReader = getCardReader(plugin, ".*ASK.*");

    logger.info("= #### Select application with AID = '{}'.", CalypsoDef.AID);

    // Get the core card selection service.
    CardSelectionService selectionService = CardSelectionServiceFactory.getService();

    // Create a card selection using the Calypso card extension.
    // Prepare the selection by adding the created Calypso card selection to the card selection
    // scenario.
    selectionService.prepareSelection(
        cardExtension.createCardSelection(
            CardSelector.builder().filterByDfName(CalypsoDef.AID).build(), true));

    // Schedule the selection scenario.
    selectionService.scheduleCardSelectionScenario(
        (ObservableReader) cardReader, ObservableReader.NotificationMode.MATCHED_ONLY);

    // Create and add an observer
    CardTransaction cardTransactionManager = new CardTransaction(cardReader, selectionService);

    ((ObservableReader) cardReader).setReaderObservationExceptionHandler(cardTransactionManager);
    ((ObservableReader) cardReader).addObserver(cardTransactionManager);
    ((ObservableReader) cardReader).startCardDetection(ObservableReader.PollingMode.REPEATING);

    logger.info("Wait for reader or card insertion/removal");

    // Wait indefinitely. CTRL-C to exit.
    synchronized (waitForEnd) {
      waitForEnd.wait();
    }

    // stop the card resource service
    CardResourceServiceProvider.getService().stop();

    // unregister plugin
    smartCardService.unregisterPlugin(plugin.getName());

    logger.info("Exit program.");
  }

  /**
   * This object is used to freeze the main thread while card operations are handle through the
   * observers callbacks. A call to the notify() method would end the program (not demonstrated
   * here).
   */
  private static final Object waitForEnd = new Object();
}
