/* **************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/
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

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.util.ArrayList;
import java.util.List;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.card.transaction.*;
import org.eclipse.keypop.card.ProxyReaderApi;
import org.eclipse.keypop.reader.CardCommunicationException;
import org.eclipse.keypop.reader.ChannelControl;
import org.eclipse.keypop.reader.InvalidCardResponseException;
import org.eclipse.keypop.reader.ReaderCommunicationException;

/**
 * Adapter of {@link FreeTransactionManager}.
 *
 * @since 3.0.0
 */
final class FreeTransactionManagerAdapter extends TransactionManagerAdapter<FreeTransactionManager>
    implements FreeTransactionManager {

  private static final String MSG_PIN_NOT_AVAILABLE = "PIN is not available for this card";

  private final TransactionContextDto transactionContext;
  private final CommandContextDto commandContext;

  /**
   * Builds a new instance.
   *
   * @param cardReader The card reader to be used.
   * @param card The selected card on which to operate the transaction.
   * @since 3.0.0
   */
  FreeTransactionManagerAdapter(ProxyReaderApi cardReader, CalypsoCardAdapter card) {
    super(cardReader, card);
    transactionContext = new TransactionContextDto(card);
    commandContext = new CommandContextDto(false, false);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  TransactionContextDto getTransactionContext() {
    return transactionContext;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  CommandContextDto getCommandContext() {
    return commandContext;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  int getPayloadCapacity() {
    return card.getPayloadCapacity();
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  void resetTransaction() {
    commands.clear();
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  void prepareNewSecureSessionIfNeeded(Command command) {
    // NOP
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  boolean canConfigureReadOnOpenSecureSession() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   * @deprecated Use {@link #processCommands(org.eclipse.keypop.reader.ChannelControl)} instead.
   */
  @Deprecated
  @Override
  public FreeTransactionManager processCommands(
      org.eclipse.keypop.calypso.card.transaction.ChannelControl channelControl) {
    try {
      return processCommands(ChannelControl.valueOf(channelControl.name()));
    } catch (CardCommunicationException e) {
      throw new CardIOException(e.getMessage(), e);
    } catch (ReaderCommunicationException e) {
      throw new ReaderIOException(e.getMessage(), e);
    } catch (InvalidCardResponseException e) {
      throw new UnexpectedCommandStatusException(e.getMessage(), e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>For each prepared command, if a pre-processing is required, then we try to execute the
   * post-processing of each of the previous commands in anticipation. If at least one
   * post-processing cannot be anticipated, then we execute the block of previous commands first.
   *
   * @since 3.2.0
   */
  @Override
  public FreeTransactionManager processCommands(ChannelControl channelControl) {
    if (commands.isEmpty()) {
      return this;
    }
    try {
      List<Command> cardRequestCommands = new ArrayList<>();
      for (Command command : commands) {
        command.finalizeRequest();
        cardRequestCommands.add(command);
      }
      executeCardCommands(cardRequestCommands, channelControl);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    } finally {
      commands.clear();
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public FreeTransactionManager prepareVerifyPin(byte[] pin) {
    try {
      Assert.getInstance()
          .notNull(pin, "pin")
          .isEqual(pin.length, CalypsoCardConstant.PIN_LENGTH, "PIN length");
      if (!card.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
      }
      commands.add(new CommandVerifyPin(getTransactionContext(), getCommandContext(), pin));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public FreeTransactionManager prepareChangePin(byte[] newPin) {
    try {
      Assert.getInstance()
          .notNull(newPin, "newPin")
          .isEqual(newPin.length, CalypsoCardConstant.PIN_LENGTH, "PIN length");
      if (!card.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
      }
      // CL-PIN-MENCRYPT.1
      commands.add(new CommandChangePin(getTransactionContext(), getCommandContext(), newPin));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }
}
