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
package org.eclipse.keyple.card.calypso.examples.UseCase8_StoredValue_DebitInSession;

import static org.eclipse.keyple.card.calypso.examples.common.ConfigurationUtil.getCardReader;
import static org.eclipse.keyple.card.calypso.examples.common.ConfigurationUtil.setupCardResourceService;

import org.eclipse.keyple.card.calypso.CalypsoExtensionService;
import org.eclipse.keyple.card.calypso.CalypsoExtensionServiceProvider;
import org.eclipse.keyple.card.calypso.card.CalypsoCard;
import org.eclipse.keyple.card.calypso.examples.common.CalypsoConstants;
import org.eclipse.keyple.card.calypso.examples.common.ConfigurationUtil;
import org.eclipse.keyple.card.calypso.transaction.CardSecuritySetting;
import org.eclipse.keyple.card.calypso.transaction.CardTransactionService;
import org.eclipse.keyple.core.service.*;
import org.eclipse.keyple.core.service.selection.CardSelectionResult;
import org.eclipse.keyple.core.service.selection.CardSelectionService;
import org.eclipse.keyple.core.service.selection.CardSelector;
import org.eclipse.keyple.plugin.pcsc.PcscPluginFactoryBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 *
 * <h1>Use Case ‘Calypso 4’ – Calypso Card authentication (PC/SC)</h1>
 *
 * <p>Here we demonstrate the debit of the Stored Value counter of a Calypso card.
 *
 * <h2>Scenario:</h2>
 *
 * <ul>
 *   <li>Sets up the card resource service to provide a Calypso SAM (C1).
 *   <li>Checks if an ISO 14443-4 card is in the reader, enables the card selection service.
 *   <li>Attempts to select the specified card (here a Calypso card characterized by its AID) with
 *       an AID-based application selection scenario.
 *   <li>Creates a {@link CardTransactionService} using {@link CardSecuritySetting} referencing the
 *       SAM profile defined in the card resource service.
 *   <li>Displays the Stored Value status, debits the Store Value within a Secure Session.
 * </ul>
 *
 * All results are logged with slf4j.
 *
 * <p>Any unexpected behavior will result in runtime exceptions.
 *
 * @since 2.0
 */
public class StoredValue_DebitInSession_Pcsc {
  private static final Logger logger =
      LoggerFactory.getLogger(StoredValue_DebitInSession_Pcsc.class);

  public static void main(String[] args) {

    // Get the instance of the SmartCardService (singleton pattern)
    SmartCardService smartCardService = SmartCardServiceProvider.getService();

    // Register the PcscPlugin with the SmartCardService, get the corresponding generic plugin in
    // return.
    Plugin plugin = smartCardService.registerPlugin(PcscPluginFactoryBuilder.builder().build());

    // Get the Calypso card extension service
    CalypsoExtensionService cardExtension = CalypsoExtensionServiceProvider.getService();

    // Verify that the extension's API level is consistent with the current service.
    smartCardService.checkCardExtension(cardExtension);

    // Get and setup the card reader
    // We suppose here, we use a ASK LoGO contactless PC/SC reader as card reader.
    Reader cardReader = getCardReader(plugin, ConfigurationUtil.CARD_READER_NAME_REGEX);

    // Configure the card resource service to provide an adequate SAM for future secure operations.
    // We suppose here, we use a Identive contact PC/SC reader as card reader.
    setupCardResourceService(
        plugin, ConfigurationUtil.SAM_READER_NAME_REGEX, CalypsoConstants.SAM_PROFILE_NAME);

    logger.info("=============== UseCase Calypso #8: Stored Value debit ==================");

    // Check if a card is present in the reader
    if (!cardReader.isCardPresent()) {
      throw new IllegalStateException("No card is present in the reader.");
    }

    logger.info("= #### Select application with AID = '{}'.", CalypsoConstants.AID);

    // Get the core card selection service.
    CardSelectionService selectionService = CardSelectionServiceFactory.getService();

    // Create a card selection using the Calypso card extension.
    // Prepare the selection by adding the created Calypso card selection to the card selection
    // scenario.
    selectionService.prepareSelection(
        cardExtension.createCardSelection(
            CardSelector.builder().filterByDfName(CalypsoConstants.AID).build(), true));

    // Actual card communication: run the selection scenario.
    CardSelectionResult selectionResult = selectionService.processCardSelectionScenario(cardReader);

    // Check the selection result.
    if (!selectionResult.hasActiveSelection()) {
      throw new IllegalStateException(
          "The selection of the application " + CalypsoConstants.AID + " failed.");
    }

    // Get the SmartCard resulting of the selection.
    CalypsoCard calypsoCard = (CalypsoCard) selectionResult.getActiveSmartCard();

    logger.info("= SmartCard = {}", calypsoCard);

    // Create security settings that reference the same SAM profile requested from the card resource
    // service.
    CardSecuritySetting cardSecuritySetting =
        CardSecuritySetting.builder()
            .setSamCardResourceProfileName(CalypsoConstants.SAM_PROFILE_NAME)
            .isLoadAndDebitSvLogRequired(true)
            .build();

    // Performs file reads using the card transaction service in non-secure mode.
    CardTransactionService cardTransaction =
        cardExtension
            .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting)
            .prepareSvGet(
                CardTransactionService.SvSettings.Operation.DEBIT,
                CardTransactionService.SvSettings.Action.DO)
            .processOpening(CardTransactionService.SessionAccessLevel.SESSION_LVL_DEBIT);

    // Display the current SV status
    logger.info("Current SV status (SV Get for DEBIT):");
    logger.info(". Balance = {}", calypsoCard.getSvBalance());
    logger.info(". Last Transaction Number = {}", calypsoCard.getSvLastTNum());

    // Display the load and debit records.
    logger.info(". Load log record = {}", calypsoCard.getSvLoadLogRecord());
    logger.info(". Debit log record = {}", calypsoCard.getSvDebitLogLastRecord());

    // Prepare an SV Debit of 2 units
    cardTransaction.prepareSvDebit(2).prepareReleaseCardChannel().processClosing();

    logger.info(
        "The Secure Session ended successfully, the stored value has been debited by 2 units.");

    logger.info("= #### End of the Calypso card processing.");

    System.exit(0);
  }
}
