package org.eclipse.keyple.card.calypso;
import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.card.transaction.ChannelControl;
import org.eclipse.keypop.calypso.card.transaction.FreeTransactionManager;
import org.eclipse.keypop.card.ProxyReaderApi;

import java.util.ArrayList;
import java.util.List;

/**
 * Adapter of {@link FreeTransactionManager}.
 * @since 3.0.0
 */
final class FreeTransactionManagerAdapter extends TransactionManagerAdapter<FreeTransactionManager> implements FreeTransactionManager {

  private static final String MSG_PIN_NOT_AVAILABLE = "PIN is not available for this card";

  final TransactionContextDto transactionContext;

  /**
   * Builds a new instance.
   * @param cardReader The card reader to be used.
   * @param card The selected card on which to operate the transaction.
   * @since 3.0.0
   */
  FreeTransactionManagerAdapter(ProxyReaderApi cardReader, CalypsoCardAdapter card) {
    super(cardReader, card, null);
    transactionContext = new TransactionContextDto(card, null);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  TransactionContextDto getTransactionContext() {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  void prepareNewSecureSessionIfNeeded(CardCommand command) {
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
   * <p>For each prepared command, if a pre-processing is required, then we try to execute the
   * post-processing of each of the previous commands in anticipation. If at least one
   * post-processing cannot be anticipated, then we execute the block of previous commands first.
   *
   * @since 3.0.0
   */
  @Override
  public FreeTransactionManager processCommands(ChannelControl channelControl) {
    if (cardCommands.isEmpty()) {
      return this;
    }
    try {
      List<CardCommand> cardRequestCommands = new ArrayList<CardCommand>();
      for (CardCommand command : cardCommands) {
        command.finalizeRequest();
        cardRequestCommands.add(command);
      }
      executeCardCommands(cardRequestCommands, channelControl);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    } finally {
      cardCommands.clear();
      if (isExtendedMode && !card.isExtendedModeSupported()) {
        isExtendedMode = false;
      }
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
      cardCommands.add(new CmdCardVerifyPin(getTransactionContext(), getCommandContext(), pin));
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
      cardCommands.add(new CmdCardChangePin(getTransactionContext(), getCommandContext(), newPin));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }
}
