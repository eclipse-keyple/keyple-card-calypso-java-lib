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
package UseCase2_ScheduledSelection;

import static org.eclipse.keyple.core.service.ReaderEvent.EventType.CARD_INSERTED;

import common.CalypsoDef;
import org.eclipse.keyple.card.calypso.card.CalypsoCard;
import org.eclipse.keyple.core.service.*;
import org.eclipse.keyple.core.service.selection.CardSelectionService;
import org.eclipse.keyple.core.service.spi.ReaderObservationExceptionHandlerSpi;
import org.eclipse.keyple.core.service.spi.ReaderObserverSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A reader Observer handles card event such as CARD_INSERTED, CARD_MATCHED, CARD_REMOVED */
class CardReaderObserver implements ReaderObserverSpi, ReaderObservationExceptionHandlerSpi {

  private static final Logger logger = LoggerFactory.getLogger(CardReaderObserver.class);
  private final Reader reader;
  private final CardSelectionService selectionService;

  /**
   * (package-private)<br>
   * Constructor.
   *
   * <p>Note: the reader is provided here for convenience but could also be retrieved from the
   * {@link SmartCardService} with its name and that of the plugin both present in the {@link
   * ReaderEvent}.
   *
   * @param reader The card reader.
   * @param selectionService The card selection service.
   */
  CardReaderObserver(Reader reader, CardSelectionService selectionService) {
    this.reader = reader;
    this.selectionService = selectionService;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public void onReaderEvent(ReaderEvent event) {
    switch (event.getEventType()) {
      case CARD_MATCHED:
        // the selection has one target, get the result at index 0
        CalypsoCard calypsoCard =
            (CalypsoCard)
                selectionService
                    .parseScheduledCardSelectionsResponse(
                        event.getScheduledCardSelectionsResponse())
                    .getActiveSmartCard();

        logger.info(
            "Observer notification: card selection was successful and produced the smart card = {}",
            calypsoCard);
        logger.info("Data read during the scheduled selection process:");
        logger.info(
            "File {}h, rec 1: FILE_CONTENT = {}",
            String.format("%02X", CalypsoDef.SFI_ENVIRONMENT_AND_HOLDER),
            calypsoCard.getFileBySfi(CalypsoDef.SFI_ENVIRONMENT_AND_HOLDER));

        logger.info("= #### End of the card processing.");

        break;

      case CARD_INSERTED:
        logger.error(
            "CARD_INSERTED event: should not have occurred because of the MATCHED_ONLY selection mode chosen.");
        break;

      case CARD_REMOVED:
        logger.trace("There is no card inserted anymore. Return to the waiting state...");
        break;
      default:
        break;
    }

    if (event.getEventType() == CARD_INSERTED
        || event.getEventType() == ReaderEvent.EventType.CARD_MATCHED) {

      // Informs the underlying layer of the end of the card processing, in order to manage the
      // removal sequence.
      ((ObservableReader) (reader)).finalizeCardProcessing();
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public void onReaderObservationError(String pluginName, String readerName, Throwable e) {
    logger.error("An exception occurred in plugin '{}', reader '{}'.", pluginName, readerName, e);
  }
}
