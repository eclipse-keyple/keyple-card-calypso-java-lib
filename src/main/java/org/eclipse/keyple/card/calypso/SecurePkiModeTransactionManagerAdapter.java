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
import java.util.Collections;
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
import org.eclipse.keypop.card.ApduResponseApi;
import org.eclipse.keypop.card.ProxyReaderApi;
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
  private final TransactionContextDto transactionContext;
  private final AsymmetricCryptoSecuritySettingAdapter asymmetricCryptoSecuritySetting;
  private final CardTransactionCryptoExtension cryptoExtension;
  private final SecureRandom secureRandom = new SecureRandom();
  private final int payloadCapacity;

  private ChannelControl originalChannelControl;
  private boolean isGetDataCardCertificatePrepared;
  private boolean isGetDataCaCertificatePrepared;

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
    isGetDataCaCertificatePrepared = false;
    disablePreOpenMode();
    commands.clear();
    if (transactionContext.isSecureSessionOpen()) {
      try {
        CommandCloseSecureSession cancelSecureSessionCommand =
            new CommandCloseSecureSession(transactionContext, getCommandContext(), true);
        cancelSecureSessionCommand.finalizeRequest();
        List<Command> commands = new ArrayList<Command>(1);
        commands.add(cancelSecureSessionCommand);
        executeCardCommands(commands, ChannelControl.KEEP_OPEN);
      } catch (RuntimeException e) {
        logger.debug("Secure session abortion error: {}", e.getMessage());
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
    } else if (tag == GetDataTag.CA_CERTIFICATE) {
      isGetDataCaCertificatePrepared = true;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public SecurePkiModeTransactionManager processCommands(ChannelControl channelControl) {
    if (commands.isEmpty()) {
      return this;
    }
    try {
      // In the case that the CA certificate is missing before the parsing of the response to
      // the "open secure session" command, we seamlessly trigger the execution of Get Data commands
      // to fetch it. Depending on the current status of the session, these commands might also be
      // integrated to the session hash. We need to keep the channel open and close or keep it open
      // as expected after the execution of the Get Data commands (role of originalChannelControl).
      originalChannelControl = channelControl;
      if (card.getCaCertificate().length == 0 && !isGetDataCaCertificatePrepared) {
        executeCardCommands(commands, ChannelControl.KEEP_OPEN);
      } else {
        executeCardCommands(commands, channelControl);
      }
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    } finally {
      commands.clear();
    }
    return this;
  }

  /**
   * Parses the command's response and performs the necessary actions based on the command type.
   *
   * @param command The command.
   * @param apduResponse The response from the card.
   * @throws CardCommandException If there is an error in the card command.
   * @since 3.1.0
   */
  @Override
  void parseCommandResponse(Command command, ApduResponseApi apduResponse)
      throws CardCommandException {
    if (command.getCommandRef() == CardCommandRef.OPEN_SECURE_SESSION) {
      checkCardCertificateAndGetCardPublicKey();
    }
    command.parseResponse(apduResponse);
  }

  /** Extracts the card public key using the PKI chain of trust and place it into the card image. */
  private void checkCardCertificateAndGetCardPublicKey() {

    // Parse the card certificate raw data
    CardCertificateSpi cardCertificateSpi = parseCardCertificate();

    if (!Arrays.equals(
        card.getApplicationSerialNumber(), cardCertificateSpi.getCardSerialNumber())) {
      throw new InvalidCertificateException(
          "Card serial number and certificate card serial number mismatch.");
    }

    // Try to retrieve the issuer certificate content from the store
    CaCertificateContentSpi caCertificateContentSpi =
        asymmetricCryptoSecuritySetting.getCaCertificate(
            cardCertificateSpi.getIssuerPublicKeyReference());

    // If the issuer certificate content is not already registered, then retrieve it from the card
    if (caCertificateContentSpi == null) {
      // Read the CA certificate from the card using the original channel control
      readCaCertificate();
      // Parse the CA certificate raw data
      CaCertificateSpi caCertificateSpi = parseCaCertificate();
      // Register the CA certificate into the store
      asymmetricCryptoSecuritySetting.addCaCertificate((CaCertificate) caCertificateSpi);
      // Retrieve the CA certificate content from the store
      caCertificateContentSpi =
          asymmetricCryptoSecuritySetting.getCaCertificate(
              cardCertificateSpi.getIssuerPublicKeyReference());
    } else {
      // Force the closing of the channel if originally requested
      if (originalChannelControl == ChannelControl.CLOSE_AFTER) {
        executeCardCommands(Collections.<Command>emptyList(), ChannelControl.CLOSE_AFTER);
      }
    }

    // Check the card certificate using the issuer certificate content and extract the public key
    CardPublicKeySpi cardPublicKeySpi;
    try {
      cardPublicKeySpi =
          cardCertificateSpi.checkCertificateAndGetPublicKey(caCertificateContentSpi);
    } catch (CertificateValidationException e) {
      throw new InvalidCertificateException("Invalid card certificate: " + e.getMessage(), e);
    } catch (AsymmetricCryptoException e) {
      throw new CryptoException(
          "An error occurred while checking the card certificate: " + e.getMessage(), e);
    }

    // Save the card public key into the card image
    card.setCardPublicKeySpi(cardPublicKeySpi);
  }

  /**
   * Parses the card certificate placed into the card image.
   *
   * @return A non-null reference.
   * @throws IllegalStateException If the certificate parser is not registered.
   */
  private CardCertificateSpi parseCardCertificate() {
    byte[] cardCertificateBytes = card.getCardCertificate();
    CardCertificateParserSpi cardCertificateParser =
        asymmetricCryptoSecuritySetting.getCardCertificateParser(cardCertificateBytes[0]);
    if (cardCertificateParser == null) {
      throw new IllegalStateException(
          "No certificate parser registered for type " + HexUtil.toHex(cardCertificateBytes[0]));
    }
    return cardCertificateParser.parseCertificate(cardCertificateBytes);
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
    return caCertificateParser.parseCertificate(caCertificateBytes);
  }

  /**
   * Executes Get Data commands to retrieve the CA certificate from the card. The result will
   * available in the card image.
   */
  private void readCaCertificate() {
    List<Command> commands = new ArrayList<Command>(2);
    commands.add(
        new CommandGetDataCertificate(transactionContext, getCommandContext(), false, true));
    commands.add(
        new CommandGetDataCertificate(transactionContext, getCommandContext(), false, false));
    executeCardCommands(commands, originalChannelControl);
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
        new CommandOpenSecureSession(
            transactionContext,
            getCommandContext(),
            terminalChallenge,
            asymmetricCryptoSecuritySetting));
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
