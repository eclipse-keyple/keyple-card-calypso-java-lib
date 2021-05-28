/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://www.calypsonet-asso.org/
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

import java.util.ArrayList;
import java.util.List;
import org.eclipse.keyple.card.calypso.transaction.CalypsoCardTransactionIllegalStateException;
import org.eclipse.keyple.card.calypso.transaction.CardTransactionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Handles a list {@link AbstractCardCommandBuilder} updated by the "prepare" methods of
 * CardTransactionService.
 *
 * <p>Keeps builders between the time the commands are created and the time their responses are
 * parsed.
 *
 * <p>A flag (preparedCommandsProcessed) is used to manage the reset of the command list. It allows
 * the builders to be kept until the application creates a new list of commands.
 *
 * <p>This flag is set when invoking the method notifyCommandsProcessed and reset when a new
 * AbstractCardCommandBuilder is added or when a attempt
 *
 * @since 2.0
 */
class CardCommandManager {
  private static final Logger logger = LoggerFactory.getLogger(CardCommandManager.class);

  /** The list to contain the prepared commands */
  private final List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>>
      cardCommands =
          new ArrayList<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>>();

  private CalypsoCardCommand svLastCommand;
  private CardTransactionService.SvSettings.Operation svOperation;
  private boolean svOperationComplete = false;

  /**
   * (package-private)<br>
   * Constructor
   */
  CardCommandManager() {}

  /**
   * (package-private)<br>
   * Add a regular command to the builders and parsers list.
   *
   * @param commandBuilder the command builder.
   */
  void addRegularCommand(
      AbstractCardCommandBuilder<? extends AbstractCardResponseParser> commandBuilder) {
    cardCommands.add(commandBuilder);
  }

  /**
   * (package-private)<br>
   * Add a StoredValue command to the builders and parsers list.
   *
   * <p>Set up a mini state machine to manage the scheduling of Stored Value commands.
   *
   * <p>The {@link CardTransactionService.SvSettings.Operation} and {@link
   * CardTransactionService.SvSettings.Action} are also used to check the consistency of the SV
   * process.
   *
   * <p>The svOperationPending flag is set when an SV operation (Reload/Debit/Undebit) command is
   * added.
   *
   * @param commandBuilder the StoredValue command builder.
   * @param svOperation the type of the current SV operation (Realod/Debit/Undebit).
   * @throws IllegalStateException if the provided command is not an SV command
   * @throws CalypsoCardTransactionIllegalStateException if the SV API is not properly used.
   */
  void addStoredValueCommand(
      AbstractCardCommandBuilder<? extends AbstractCardResponseParser> commandBuilder,
      CardTransactionService.SvSettings.Operation svOperation) {
    // Check the logic of the SV command sequencing
    switch (commandBuilder.getCommandRef()) {
      case SV_GET:
        this.svOperation = svOperation;
        break;
      case SV_RELOAD:
      case SV_DEBIT:
      case SV_UNDEBIT:
        if (!cardCommands.isEmpty()) {
          throw new CalypsoCardTransactionIllegalStateException(
              "This SV command can only be placed in the first position in the list of prepared commands");
        }

        if (svLastCommand != CalypsoCardCommand.SV_GET) {
          // @see Calypso Layer ID 8.07/8.08 (200108)
          throw new IllegalStateException("This SV command must follow an SV Get command");
        }

        // here, we expect the builder and the SV operation to be consistent
        if (svOperation != this.svOperation) {
          logger.error("Sv operation = {}, current command = {}", this.svOperation, svOperation);
          throw new CalypsoCardTransactionIllegalStateException("Inconsistent SV operation.");
        }
        this.svOperation = svOperation;
        svOperationComplete = true;
        break;
      default:
        throw new IllegalStateException("An SV command is expected.");
    }
    svLastCommand = commandBuilder.getCommandRef();

    cardCommands.add(commandBuilder);
  }

  /**
   * (package-private)<br>
   * Informs that the commands have been processed.
   *
   * <p>Just record the information. The initialization of the list of commands will be done only
   * the next time a command is added, this allows access to the parsers contained in the list..
   */
  void notifyCommandsProcessed() {
    cardCommands.clear();
  }

  /**
   * (package-private)<br>
   *
   * @return The current AbstractCardCommandBuilder list
   */
  List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>> getCardCommandBuilders() {
    return cardCommands;
  }

  /**
   * (package-private)<br>
   *
   * @return True if the {@link CardCommandManager} has commands
   */
  boolean hasCommands() {
    return !cardCommands.isEmpty();
  }

  /**
   * (package-private)<br>
   * Indicates whether an SV Operation has been completed (Reload/Debit/Undebit requested) <br>
   * This method is dedicated to triggering the signature verification after an SV transaction has
   * been executed. It is a single-use method, as the flag is systematically reset to false after it
   * is called.
   *
   * @return True if a reload or debit command has been requested
   */
  boolean isSvOperationCompleteOneTime() {
    boolean flag = svOperationComplete;
    svOperationComplete = false;
    return flag;
  }
}
