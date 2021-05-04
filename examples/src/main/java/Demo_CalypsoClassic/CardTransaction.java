/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://www.calypsonet-asso.org/
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

import common.CalypsoDef;
import org.eclipse.keyple.card.calypso.CalypsoExtensionServiceProvider;
import org.eclipse.keyple.card.calypso.card.CalypsoCard;
import org.eclipse.keyple.card.calypso.transaction.CardSecuritySetting;
import org.eclipse.keyple.card.calypso.transaction.CardTransactionService;
import org.eclipse.keyple.core.service.ObservableReader;
import org.eclipse.keyple.core.service.Reader;
import org.eclipse.keyple.core.service.ReaderEvent;
import org.eclipse.keyple.core.service.SmartCardServiceProvider;
import org.eclipse.keyple.core.service.selection.CardSelectionService;
import org.eclipse.keyple.core.service.spi.ReaderObservationExceptionHandlerSpi;
import org.eclipse.keyple.core.service.spi.ReaderObserverSpi;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A reader Observer handles card event such as CARD_INSERTED, CARD_MATCHED, CARD_REMOVED */
class CardTransaction implements ReaderObserverSpi, ReaderObservationExceptionHandlerSpi {

  private static final Logger logger = LoggerFactory.getLogger(CardTransaction.class);

  private final Reader calypsoReader;
  private final CardSelectionService selectionService;
  private final CardSecuritySetting cardSecuritySetting;

  public CardTransaction(Reader calypsoCardReader, CardSelectionService selectionService) {
    this.calypsoReader = calypsoCardReader;
    this.selectionService = selectionService;
    cardSecuritySetting =
        CardSecuritySetting.builder().setSamCardResourceProfileName("SAM C1").build();
  }

  @Override
  public void onReaderEvent(ReaderEvent event) {

    logger.info(
        "Event: PLUGINNAME = {}, READERNAME = {}, EVENT = {}",
        event.getPluginName(),
        event.getReaderName(),
        event.getEventType().name());

    switch (event.getEventType()) {
      case CARD_MATCHED:
        // the selection has one target, get the result at index 0
        CalypsoCard calypsoCard =
            (CalypsoCard)
                selectionService
                    .parseScheduledCardSelectionsResponse(
                        event.getScheduledCardSelectionsResponse())
                    .getActiveSmartCard();

        try {
          // open secure session DEBIT and read file SFI=07h
          CardTransactionService cardTransaction =
              CalypsoExtensionServiceProvider.getService()
                  .createCardTransaction(calypsoReader, calypsoCard, cardSecuritySetting)
                  .prepareReadRecordFile(
                      CalypsoDef.SFI_ENVIRONMENT_AND_HOLDER, CalypsoDef.RECORD_NUMBER_1)
                  .processOpening(CardTransactionService.SessionAccessLevel.SESSION_LVL_DEBIT);

          // read file SFI=08h
          cardTransaction
              .prepareReadRecordFile(
                  CalypsoDef.SFI_EVENT_LOG, CalypsoDef.RECORD_NUMBER_1, 3, CalypsoDef.REC_SIZE)
              .processCardCommands();

          // append data to file SFI=08h, request channel closing, close secure session.
          cardTransaction
              .prepareAppendRecord(CalypsoDef.SFI_EVENT_LOG, ByteArrayUtil.fromHex("11223344"))
              .prepareReleaseCardChannel()
              .processClosing();

          logger.info("## The transaction was successful ##");
        } catch (Exception e) {
          logger.error(
              "An exception '{}' occurred while processing the Calypso Card transaction: {}",
              e.getClass().getName(),
              e.getMessage());
        }
        break;

      case CARD_REMOVED:
        if (event.getEventType() != ReaderEvent.EventType.CARD_REMOVED) {
          ((ObservableReader)
                  (SmartCardServiceProvider.getService()
                      .getPlugin(event.getPluginName())
                      .getReader(event.getReaderName())))
              .finalizeCardProcessing();
        }
        break;

      default:
        break;
    }
  }

  @Override
  public void onReaderObservationError(String pluginName, String readerName, Throwable e) {
    logger.error("An exception occurred in plugin '{}', reader '{}'.", pluginName, readerName, e);
  }
}
