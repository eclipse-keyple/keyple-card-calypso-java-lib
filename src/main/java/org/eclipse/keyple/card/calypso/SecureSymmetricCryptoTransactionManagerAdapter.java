package org.eclipse.keyple.card.calypso;

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.card.WriteAccessLevel;
import org.eclipse.keypop.calypso.card.card.CalypsoCard;
import org.eclipse.keypop.calypso.card.transaction.*;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoIOException;
import org.eclipse.keypop.card.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link SecureSymmetricCryptoTransactionManager}.
 *
 * @param <T> The type of the lowest level child object.
 * @since 3.0.0
 */
class SecureSymmetricCryptoTransactionManagerAdapter<T extends SecureSymmetricCryptoTransactionManager<T>> extends SecureTransactionManagerAdapter<T> implements SecureSymmetricCryptoTransactionManager<T> {

  private static final Logger logger = LoggerFactory.getLogger(SecureSymmetricCryptoTransactionManagerAdapter.class);

  /**
   * Builds a new instance.
   *
   * @param cardReader                     The card reader to be used.
   * @param card                           The selected card on which to operate the transaction.
   * @param symmetricCryptoSecuritySetting The symmetric crypto security setting to be used.
   * @since 3.0.0
   */
  SecureSymmetricCryptoTransactionManagerAdapter(ProxyReaderApi cardReader, CalypsoCardAdapter card, SymmetricCryptoSecuritySettingAdapter symmetricCryptoSecuritySetting) {
    super(cardReader, card, symmetricCryptoSecuritySetting);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public T prepareOpenSecureSession(WriteAccessLevel writeAccessLevel) {
    try {
      Assert.getInstance().notNull(writeAccessLevel, "writeAccessLevel");
      checkNoSecureSession();
      if (card.getPreOpenWriteAccessLevel() != null
              && card.getPreOpenWriteAccessLevel() != writeAccessLevel) {
        logger.warn(
                "Pre-open mode cancelled because writeAccessLevel '{}' mismatches the writeAccessLevel used for"
                        + " pre-open mode '{}'",
                writeAccessLevel,
                card.getPreOpenWriteAccessLevel());
        disablePreOpenMode();
      }
      cardCommands.add(
              new CmdCardOpenSecureSession(
                      transactionContext,
                      getCommandContext(),
                      symmetricCryptoSecuritySetting,
                      writeAccessLevel,
                      isExtendedMode));
      this.writeAccessLevel = writeAccessLevel; // CL-KEY-INDEXPO.1
      isSecureSessionOpen = true;
      isEncryptionActive = false;
      modificationsCounter = card.getModificationsCounter();
      nbPostponedData = 0;
      svPostponedDataIndex = -1;
      isSvOperationInSecureSession = false;
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public T prepareSvGet(SvOperation svOperation, SvAction svAction) {
    try {
      Assert.getInstance().notNull(svOperation, "svOperation").notNull(svAction, "svAction");

      if (!card.isSvFeatureAvailable()) {
        throw new UnsupportedOperationException("Stored Value is not available for this card.");
      }

      if (symmetricCryptoSecuritySetting.isSvLoadAndDebitLogEnabled() && (!isExtendedMode)) {
        // @see Calypso Layer ID 8.09/8.10 (200108): both reload and debit logs are requested
        // for a non rev3.2 card add two SvGet commands (for RELOAD then for DEBIT).
        // CL-SV-GETNUMBER.1
        SvOperation operation1 =
                svOperation == SvOperation.RELOAD ? SvOperation.DEBIT : SvOperation.RELOAD;
        cardCommands.add(
                new CmdCardSvGet(transactionContext, getCommandContext(), operation1, false));
      }
      cardCommands.add(
              new CmdCardSvGet(transactionContext, getCommandContext(), svOperation, isExtendedMode));
      isSvGet = true;
      this.svOperation = svOperation;
      this.svAction = svAction;
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public T prepareSvReload(int amount, byte[] date, byte[] time, byte[] free) {
    try {
      Assert.getInstance()
              .isInRange(
                      amount,
                      CalypsoCardConstant.SV_LOAD_MIN_VALUE,
                      CalypsoCardConstant.SV_LOAD_MAX_VALUE,
                      "amount")
              .notNull(date, "date")
              .notNull(time, "time")
              .notNull(free, "free")
              .isEqual(date.length, 2, "date")
              .isEqual(time.length, 2, "time")
              .isEqual(free.length, 2, "free");

      checkSvModifyingCommandPreconditions(SvOperation.RELOAD);

      CmdCardSvReload command =
              new CmdCardSvReload(
                      transactionContext, getCommandContext(), amount, date, time, free, isExtendedMode);
      prepareNewSecureSessionIfNeeded(command);
      cardCommands.add(command);

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * Checks if the preconditions of an SV modifying command are satisfied and updates the
   * corresponding flags.
   *
   * @throws IllegalStateException If preconditions are not satisfied.
   */
  private void checkSvModifyingCommandPreconditions(SvOperation svOperation) {
    // CL-SV-GETDEBIT.1
    // CL-SV-GETRLOAD.1
    if (!isSvGet) {
      throw new IllegalStateException("SV modifying command must follow an SV Get command");
    }
    isSvGet = false;
    if (svOperation != this.svOperation) {
      throw new IllegalStateException("Inconsistent SV operation");
    }
    // CL-SV-1PCSS.1
    if (isSecureSessionOpen) {
      if (isSvOperationInSecureSession) {
        throw new IllegalStateException(
                "Only one SV modifying command is allowed per Secure Session");
      }
      isSvOperationInSecureSession = true;
      svPostponedDataIndex = nbPostponedData;
      nbPostponedData++;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public T prepareSvReload(int amount) {
    byte[] zero = {0x00, 0x00};
    prepareSvReload(amount, zero, zero, zero);
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public T prepareSvDebit(int amount, byte[] date, byte[] time) {
    try {
      /* @see Calypso Layer ID 8.02 (200108) */
      // CL-SV-DEBITVAL.1
      Assert.getInstance()
              .isInRange(
                      amount,
                      CalypsoCardConstant.SV_DEBIT_MIN_VALUE,
                      CalypsoCardConstant.SV_DEBIT_MAX_VALUE,
                      "amount")
              .notNull(date, "date")
              .notNull(time, "time")
              .isEqual(date.length, 2, "date")
              .isEqual(time.length, 2, "time");

      checkSvModifyingCommandPreconditions(SvOperation.DEBIT);

      CmdCardSvDebitOrUndebit command =
              new CmdCardSvDebitOrUndebit(
                      svAction == SvAction.DO,
                      transactionContext,
                      getCommandContext(),
                      amount,
                      date,
                      time,
                      isExtendedMode,
                      symmetricCryptoSecuritySetting.isSvNegativeBalanceAuthorized());
      prepareNewSecureSessionIfNeeded(command);
      cardCommands.add(command);

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public T prepareSvDebit(int amount) {
    byte[] zero = {0x00, 0x00};
    prepareSvDebit(amount, zero, zero);
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public T prepareInvalidate() {
    try {
      if (card.isDfInvalidated()) {
        throw new IllegalStateException("Card already invalidated");
      }
      CmdCardInvalidate command = new CmdCardInvalidate(transactionContext, getCommandContext());
      prepareNewSecureSessionIfNeeded(command);
      cardCommands.add(command);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public T prepareRehabilitate() {
    try {
      if (!card.isDfInvalidated()) {
        throw new IllegalStateException("Card not invalidated");
      }
      CmdCardRehabilitate command =
              new CmdCardRehabilitate(transactionContext, getCommandContext());
      prepareNewSecureSessionIfNeeded(command);
      cardCommands.add(command);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public T prepareChangeKey(int keyIndex, byte newKif, byte newKvc, byte issuerKif, byte issuerKvc) {
    try {
      if (card.getProductType() == CalypsoCard.ProductType.BASIC) {
        throw new UnsupportedOperationException("'Change Key' command not available for this card");
      }
      checkNoSecureSession();
      Assert.getInstance().isInRange(keyIndex, 1, 3, "keyIndex");
      // CL-KEY-CHANGE.1
      cardCommands.add(new CmdCardGetChallenge(transactionContext, getCommandContext()));
      cardCommands.add(
              new CmdCardChangeKey(
                      transactionContext,
                      getCommandContext(),
                      (byte) keyIndex,
                      newKif,
                      newKvc,
                      issuerKif,
                      issuerKvc));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.4
   */
  @Override
  public void initCryptoContextForNextTransaction() {
    if (!cardCommands.isEmpty()) {
      throw new IllegalStateException("Unprocessed card commands are pending");
    }
    try {
      symmetricCryptoTransactionManagerSpi.preInitTerminalSecureSessionContext();
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }
  }
}
