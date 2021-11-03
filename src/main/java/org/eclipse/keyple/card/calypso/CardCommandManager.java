/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/
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
import org.calypsonet.terminal.calypso.transaction.SvAction;
import org.calypsonet.terminal.calypso.transaction.SvOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Handles a list of {@link AbstractCardCommand} updated by the "prepare" methods of
 * CardTransactionManager.
 *
 * <p>Keeps commands between the time the commands are created and the time their responses are
 * parsed.
 *
 * <p>A flag (preparedCommandsProcessed) is used to manage the reset of the command list. It allows
 * the commands to be kept until the application creates a new list of commands.
 *
 * <p>This flag is set when invoking the method notifyCommandsProcessed and reset when a new
 * AbstractCardCommand is added.
 *
 * @since 2.0.0
 */
class CardCommandManager {
  private static final Logger logger = LoggerFactory.getLogger(CardCommandManager.class);

  /** The list to contain the prepared commands */
  private final List<AbstractCardCommand> cardCommands = new ArrayList<AbstractCardCommand>();

  private CalypsoCardCommand svLastCommand;
  private SvOperation svOperation;
  private boolean svOperationComplete = false;

  /**
   * (package-private)<br>
   * Constructor
   */
  CardCommandManager() {}

  /**
   * (package-private)<br>
   * Add a regular command to the list.
   *
   * @param command the command.
   * @since 2.0.0
   */
  void addRegularCommand(AbstractCardCommand command) {
    cardCommands.add(command);
  }

  /**
   * (package-private)<br>
   * Add a StoredValue command to the list.
   *
   * <p>Set up a mini state machine to manage the scheduling of Stored Value commands.
   *
   * <p>The {@link SvOperation} and {@link SvAction} are also used to check the consistency of the
   * SV process.
   *
   * <p>The svOperationPending flag is set when an SV operation (Reload/Debit/Undebit) command is
   * added.
   *
   * @param command the StoredValue command.
   * @param svOperation the type of the current SV operation (Reload/Debit/Undebit).
   * @throws IllegalStateException if the provided command is not an SV command or not properly
   *     used.
   * @since 2.0.0
   */
  void addStoredValueCommand(AbstractCardCommand command, SvOperation svOperation) {
    // Check the logic of the SV command sequencing
    switch (command.getCommandRef()) {
      case SV_GET:
        this.svOperation = svOperation;
        break;
      case SV_RELOAD:
      case SV_DEBIT:
      case SV_UNDEBIT:
        if (!cardCommands.isEmpty()) {
          throw new IllegalStateException(
              "This SV command can only be placed in the first position in the list of prepared commands");
        }

        if (svLastCommand != CalypsoCardCommand.SV_GET) {
          // @see Calypso Layer ID 8.07/8.08 (200108)
          throw new IllegalStateException("This SV command must follow an SV Get command");
        }

        // here, we expect the command and the SV operation to be consistent
        if (svOperation != this.svOperation) {
          logger.error("Sv operation = {}, current command = {}", this.svOperation, svOperation);
          throw new IllegalStateException("Inconsistent SV operation.");
        }
        svOperationComplete = true;
        break;
      default:
        throw new IllegalStateException("An SV command is expected.");
    }
    svLastCommand = command.getCommandRef();

    cardCommands.add(command);
  }

  /**
   * (package-private)<br>
   * Informs that the commands have been processed.
   *
   * <p>Just record the information. The initialization of the list of commands will be done only
   * the next time a command is added, this allows access to the commands contained in the list.
   *
   * @since 2.0.0
   */
  void notifyCommandsProcessed() {
    cardCommands.clear();
  }

  /**
   * (package-private)<br>
   *
   * @return The current AbstractCardCommand list
   * @since 2.0.0
   */
  List<AbstractCardCommand> getCardCommands() {
    return cardCommands;
  }

  /**
   * (package-private)<br>
   *
   * @return True if the {@link CardCommandManager} has commands
   * @since 2.0.0
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
   * @return True if a "reload" or "debit" command has been requested
   * @since 2.0.0
   */
  boolean isSvOperationCompleteOneTime() {
    boolean flag = svOperationComplete;
    svOperationComplete = false;
    return flag;
  }
}
