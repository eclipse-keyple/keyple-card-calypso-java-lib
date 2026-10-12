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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.GetDataTag;
import org.eclipse.keypop.calypso.card.transaction.*;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificate;
import org.eclipse.keypop.calypso.card.transaction.spi.CardTransactionCryptoExtension;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.*;
import org.eclipse.keypop.calypso.crypto.asymmetric.transaction.spi.AsymmetricCryptoCardTransactionManagerSpi;
import org.eclipse.keypop.card.ProxyReaderApi;
import org.eclipse.keypop.reader.CardCommunicationException;
import org.eclipse.keypop.reader.ChannelControl;
import org.eclipse.keypop.reader.InvalidCardResponseException;
import org.eclipse.keypop.reader.ReaderCommunicationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link SecurePkiModeTransactionManager}.
 *
 * @since 3.1.0
 */
final class SecurePkiModeTransactionManagerAdapter
    extends SecureTransactionManagerAdapter<SecurePkiModeTransactionManager>
    implements SecurePkiModeTransactionManager {

  private static final Logger logger =
      LoggerFactory.getLogger(SecurePkiModeTransactionManagerAdapter.class);

  private static final String MSG_PIN_NOT_AVAILABLE = "PIN is not available for this card";
  private static final String MSG_INVALID_CARD_CERTIFICATE = "Invalid card certificate";
  private static final String MSG_INVALID_CA_CERTIFICATE = "Invalid CA certificate";
  private final TransactionContextDto transactionContext;
  private final AsymmetricCryptoSecuritySettingAdapter asymmetricCryptoSecuritySetting;
  private final CardTransactionCryptoExtension cryptoExtension;
  private final SecureRandom secureRandom = new SecureRandom();
  private final int payloadCapacity;

  private boolean isGetDataCardCertificatePrepared;

  /**
   * Builds a new instance.
   *
   * @param cardReader The card reader to be used.
   * @param card The selected card on which to operate the transaction.
   * @param asymmetricCryptoSecuritySetting The asymmetric crypto security setting to be used.
   * @since 3.1.0
   */
  SecurePkiModeTransactionManagerAdapter(
      ProxyReaderApi cardReader,
      CalypsoCardAdapter card,
      AsymmetricCryptoSecuritySettingAdapter asymmetricCryptoSecuritySetting) {
    super(cardReader, card);

    this.asymmetricCryptoSecuritySetting = asymmetricCryptoSecuritySetting;

    payloadCapacity = card.getPayloadCapacity();

    AsymmetricCryptoCardTransactionManagerSpi asymmetricCryptoCardTransactionManagerSpi =
        asymmetricCryptoSecuritySetting
            .getCryptoCardTransactionManagerFactorySpi()
            .createCardTransactionManager();

    cryptoExtension = (CardTransactionCryptoExtension) asymmetricCryptoCardTransactionManagerSpi;

    transactionContext = new TransactionContextDto(card, asymmetricCryptoCardTransactionManagerSpi);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  void resetCommandContext() {
    isSecureSessionOpen = false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  TransactionContextDto getTransactionContext() {
    return transactionContext;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  CommandContextDto getCommandContext() {
    return new CommandContextDto(isSecureSessionOpen, false);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  int getPayloadCapacity() {
    return payloadCapacity;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  void resetTransaction() {
    resetCommandContext();
    isGetDataCardCertificatePrepared = false;
    disablePreOpenMode();
    commands.clear();
    if (transactionContext.isSecureSessionOpen()) {
      try {
        CommandCloseSecureSession cancelSecureSessionCommand =
            new CommandCloseSecureSession(transactionContext, getCommandContext(), true);
        cancelSecureSessionCommand.finalizeRequest();
        List<Command> commands = new ArrayList<>(1);
        commands.add(cancelSecureSessionCommand);
        executeCardCommands(commands, ChannelControl.KEEP_OPEN);
      } catch (RuntimeException e) {
        logger.warn("Failed to abort secure session [reason={}]", e.getMessage());
      } finally {
        card.restoreFiles();
        transactionContext.setSecureSessionOpen(false);
      }
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  void prepareNewSecureSessionIfNeeded(Command command) {
    // NOP
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  boolean canConfigureReadOnOpenSecureSession() {
    return isSecureSessionOpen
        && !commands.isEmpty()
        && commands.get(commands.size() - 1).getCommandRef() == CardCommandRef.OPEN_SECURE_SESSION
        && !((CommandOpenSecureSession) commands.get(commands.size() - 1)).isReadModeConfigured();
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public SecurePkiModeTransactionManager prepareVerifyPin(byte[] pin) {
    try {
      Assert.getInstance()
          .notNull(pin, "pin")
          .isEqual(pin.length, CalypsoCardConstant.PIN_LENGTH, "PIN length");
      if (!card.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
      }
      commands.add(new CommandVerifyPin(transactionContext, getCommandContext(), pin));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public SecurePkiModeTransactionManager prepareChangePin(byte[] newPin) {
    try {
      Assert.getInstance()
          .notNull(newPin, "newPin")
          .isEqual(newPin.length, CalypsoCardConstant.PIN_LENGTH, "PIN length");
      if (!card.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
      }
      // CL-PIN-MENCRYPT.1
      commands.add(new CommandChangePin(transactionContext, getCommandContext(), newPin));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public SecurePkiModeTransactionManager prepareGetData(GetDataTag tag) {
    super.prepareGetData(tag);
    if (tag == GetDataTag.CARD_CERTIFICATE) {
      isGetDataCardCertificatePrepared = true;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   * @deprecated Use {@link #processCommands(org.eclipse.keypop.reader.ChannelControl)} instead.
   */
  @Deprecated
  @Override
  public SecurePkiModeTransactionManager processCommands(
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
   * @since 3.2.0
   */
  @Override
  public SecurePkiModeTransactionManager processCommands(ChannelControl channelControl) {
    if (commands.isEmpty()) {
      return this;
    }
    try {
      List<Command> remainingCommands = commands;
      int openSecureSessionIndex = getOpenSecureSessionIndex();
      if (openSecureSessionIndex != -1) {
        // The card public key must be established before the opening of the secure session,
        // because the CA certificate may have to be read from the card and Get Data is not
        // allowed within a secure session.
        List<Command> commandsBeforeOpening = commands.subList(0, openSecureSessionIndex);
        if (containsGetDataCertificate(commandsBeforeOpening)) {
          executeCardCommands(commandsBeforeOpening, ChannelControl.KEEP_OPEN);
          remainingCommands = commands.subList(openSecureSessionIndex, commands.size());
        }
        checkCardCertificateAndGetCardPublicKey();
      }
      executeCardCommands(remainingCommands, channelControl);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    } finally {
      commands.clear();
    }
    return this;
  }

  /**
   * Returns the index of the first "Open Secure Session" command in the prepared commands.
   *
   * @return -1 if no such command is prepared.
   */
  private int getOpenSecureSessionIndex() {
    for (int i = 0; i < commands.size(); i++) {
      if (commands.get(i).getCommandRef() == CardCommandRef.OPEN_SECURE_SESSION) {
        return i;
      }
    }
    return -1;
  }

  /**
   * Indicates whether the provided commands contain a Get Data command for a certificate.
   *
   * @param commands The commands.
   * @return true if at least one command is a {@link CommandGetDataCertificate}.
   */
  private static boolean containsGetDataCertificate(List<Command> commands) {
    for (Command command : commands) {
      if (command instanceof CommandGetDataCertificate) {
        return true;
      }
    }
    return false;
  }

  /**
   * Extracts the card public key using the PKI chain of trust and place it into the card image.
   *
   * <p>Must be invoked before the opening of the secure session, since the CA certificate may have
   * to be read from the card.
   */
  private void checkCardCertificateAndGetCardPublicKey() {

    // Parse the card certificate raw data
    CardCertificateSpi cardCertificateSpi = parseCardCertificate();

    if (!Arrays.equals(
        card.getApplicationSerialNumber(), cardCertificateSpi.getCardSerialNumber())) {
      throw new InvalidCertificateException(
          "Card serial number and certificate card serial number mismatch");
    }

    // Try to retrieve the issuer certificate content from the store
    CaCertificateContentSpi caCertificateContentSpi =
        asymmetricCryptoSecuritySetting.getCaCertificate(
            cardCertificateSpi.getIssuerPublicKeyReference());

    // If the issuer certificate content is not already registered, then retrieve it from the card
    // (unless it has already been read with a Get Data command prepared by the application)
    if (caCertificateContentSpi == null) {
      if (card.getCaCertificate().length == 0) {
        readCaCertificate();
      }
      // Parse the CA certificate raw data
      CaCertificateSpi caCertificateSpi = parseCaCertificate();
      // Register the CA certificate into the store
      asymmetricCryptoSecuritySetting.addCaCertificate((CaCertificate) caCertificateSpi);
      // Retrieve the CA certificate content from the store
      caCertificateContentSpi =
          asymmetricCryptoSecuritySetting.getCaCertificate(
              cardCertificateSpi.getIssuerPublicKeyReference());
    }

    // Check the card certificate using the issuer certificate content and extract the public key
    CardPublicKeySpi cardPublicKeySpi;
    try {
      cardPublicKeySpi =
          cardCertificateSpi.checkCertificateAndGetPublicKey(caCertificateContentSpi);
    } catch (CertificateValidationException e) {
      throw new InvalidCertificateException(MSG_INVALID_CARD_CERTIFICATE, e);
    } catch (AsymmetricCryptoException e) {
      throw new CryptoException("Failed to check the card certificate", e);
    }

    // Save the card public key into the card image
    card.setCardPublicKeySpi(cardPublicKeySpi);
  }

  /**
   * Parses the card certificate placed into the card image.
   *
   * @return A non-null reference.
   * @throws IllegalStateException If the certificate parser is not registered.
   * @throws InvalidCertificateException If the certificate is invalid.
   */
  private CardCertificateSpi parseCardCertificate() {
    byte[] cardCertificateBytes = card.getCardCertificate();
    CardCertificateParserSpi cardCertificateParser =
        asymmetricCryptoSecuritySetting.getCardCertificateParser(cardCertificateBytes[0]);
    if (cardCertificateParser == null) {
      throw new IllegalStateException(
          "No certificate parser registered for type " + HexUtil.toHex(cardCertificateBytes[0]));
    }
    try {
      return cardCertificateParser.parseCertificate(cardCertificateBytes);
    } catch (CertificateValidationException e) {
      throw new InvalidCertificateException(MSG_INVALID_CARD_CERTIFICATE, e);
    }
  }

  /**
   * Parses the CA certificate placed into the card image.
   *
   * @return A non-null reference.
   * @throws IllegalStateException If the certificate parser is not registered.
   */
  private CaCertificateSpi parseCaCertificate() {
    byte[] caCertificateBytes = card.getCaCertificate();
    CaCertificateParserSpi caCertificateParser =
        asymmetricCryptoSecuritySetting.getCaCertificateParser(caCertificateBytes[0]);
    if (caCertificateParser == null) {
      throw new IllegalStateException(
          "No certificate parser registered for type " + HexUtil.toHex(caCertificateBytes[0]));
    }
    try {
      return caCertificateParser.parseCertificate(caCertificateBytes);
    } catch (CertificateValidationException e) {
      throw new InvalidCertificateException(MSG_INVALID_CA_CERTIFICATE, e);
    }
  }

  /**
   * Executes Get Data commands to retrieve the CA certificate from the card. The result will be
   * available in the card image.
   *
   * <p>As Get Data is not allowed within a secure session, this method must be called before its
   * opening.
   *
   * @throws IllegalStateException If a secure session is open.
   */
  private void readCaCertificate() {
    if (transactionContext.isSecureSessionOpen()) {
      throw new IllegalStateException("CA certificate cannot be read during a secure session");
    }
    CommandContextDto commandContext = new CommandContextDto(false, false);
    List<Command> commands = new ArrayList<>(2);
    commands.add(new CommandGetDataCertificate(transactionContext, commandContext, false, true));
    commands.add(new CommandGetDataCertificate(transactionContext, commandContext, false, false));
    executeCardCommands(commands, ChannelControl.KEEP_OPEN);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public <E extends CardTransactionCryptoExtension> E getCryptoExtension(
      Class<E> cryptoExtensionClass) {
    return cryptoExtensionClass.cast(cryptoExtension);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public SecurePkiModeTransactionManager prepareOpenSecureSession() {
    checkNoSecureSession();
    if (card.getCardCertificate().length == 0 && !isGetDataCardCertificatePrepared) {
      prepareGetData(GetDataTag.CARD_CERTIFICATE);
    }
    byte[] terminalChallenge = new byte[8];
    secureRandom.nextBytes(terminalChallenge);
    commands.add(
        new CommandOpenSecureSession(transactionContext, getCommandContext(), terminalChallenge));
    isSecureSessionOpen = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public SecurePkiModeTransactionManager prepareCloseSecureSession() {
    try {
      checkSecureSession();
      commands.add(new CommandCloseSecureSession(transactionContext, getCommandContext(), false));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    } finally {
      resetCommandContext();
      disablePreOpenMode();
    }
    return this;
  }
}
