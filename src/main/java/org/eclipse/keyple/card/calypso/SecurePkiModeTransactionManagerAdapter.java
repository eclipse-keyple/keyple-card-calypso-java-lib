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
import java.util.List;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.card.GetDataTag;
import org.eclipse.keypop.calypso.card.transaction.*;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificate;
import org.eclipse.keypop.calypso.card.transaction.spi.CardTransactionCryptoExtension;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CardIdentifierApi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.*;
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
  private final CardTransactionCryptoExtension cryptoExtension = null;
  private final SecureRandom rand = new SecureRandom();
  private boolean isGetCaCertificatePrepared; // TODO find where to set this flag?
  private ChannelControl originalChannelControl;

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

    transactionContext =
        new TransactionContextDto(
            card,
            asymmetricCryptoSecuritySetting
                .getCryptoCardTransactionManagerFactorySpi()
                .createCardTransactionManager());
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
    return card.getPayloadCapacity();
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  void resetTransaction() {

    resetCommandContext();
    disablePreOpenMode();
    commands.clear();
    if (getTransactionContext().isSecureSessionOpen()) {
      try {
        CommandCloseSecureSession cancelSecureSessionCommand =
            new CommandCloseSecureSession(getTransactionContext(), getCommandContext(), true);
        cancelSecureSessionCommand.finalizeRequest();
        List<Command> commands = new ArrayList<Command>(1);
        commands.add(cancelSecureSessionCommand);
        executeCardCommands(commands, ChannelControl.KEEP_OPEN);
      } catch (RuntimeException e) {
        logger.debug("Secure session abortion error: {}", e.getMessage());
      } finally {
        card.restoreFiles();
        getTransactionContext().setSecureSessionOpen(false);
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
    return !commands.isEmpty()
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
      commands.add(new CommandChangePin(getTransactionContext(), getCommandContext(), newPin));
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
  public SecurePkiModeTransactionManager processCommands(ChannelControl channelControl) {
    try {
      List<Command> cardRequestCommands = new ArrayList<Command>(commands);
      // In the event that the CA certificate is missing before the parsing of the response to
      // the "open secure session" command, we seamlessly trigger the execution of Get Data commands
      // to fetch it. Depending on the current status of the session, these commands might also be
      // integrated to the session hash. We need to keep the channel open and close or keep it open
      // as expected after the execution of the Get Data commands (role of originalChannelControl).
      originalChannelControl = channelControl;
      if (card.getCaCertificate().length == 0 && !isGetCaCertificatePrepared) {
        executeCardCommands(cardRequestCommands, ChannelControl.KEEP_OPEN);
      } else {
        executeCardCommands(cardRequestCommands, channelControl);
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
  void parseCommand(Command command, ApduResponseApi apduResponse) throws CardCommandException {
    if (command.getCommandRef() == CardCommandRef.OPEN_SECURE_SESSION) {
      extractPublicKeyThroughChainOfTrust();
    }
    command.parseResponse(apduResponse);
  }

  /** Get the card public key using the PKI chain of trust and place it into the card image. */
  private void extractPublicKeyThroughChainOfTrust() {
    // converts the raw data into a usable object
    CardCertificateSpi cardCertificateSpi = parseCardCertificate();
    // search the current settings to see if the corresponding CA certificate is available.
    CaCertificateContentSpi caCertificate =
        asymmetricCryptoSecuritySetting.getCertificate(
            cardCertificateSpi.getIssuerPublicKeyReference());
    if (caCertificate == null) {
      // the certificate is not available, execute Get Data commands to get the missing CA
      // certificate
      caCertificate = fetchAndParseCaCertificate();
    }
    // retrieve the card public key from the card certificate using the CA certificate
    CardPublicKeySpi cardPublicKeySpi =
        extractAndVerifyCardPublicKey(cardCertificateSpi, caCertificate);
    card.setCardPublicKeySpi(cardPublicKeySpi);
  }

  /**
   * Create a {@link CardPublicKeySpi} from the raw certificate placed into the card image when
   * parsing the response of the previously executed Get Data commands.
   *
   * @return The card certificate.
   */
  private CardCertificateSpi parseCardCertificate() {
    byte[] cardCertificateBytes = card.getCardCertificate();
    CardCertificateParserSpi cardCertificateParser =
        (CardCertificateParserSpi)
            asymmetricCryptoSecuritySetting.getCardCertificateParser(cardCertificateBytes[0]);
    return cardCertificateParser.parseCertificate(cardCertificateBytes);
  }

  /**
   * Executes additional Get Data commands to get the CA certificate from the card when not already
   * available.
   *
   * @return The CA certificate.
   */
  private CaCertificateContentSpi fetchAndParseCaCertificate() {
    executeGetCaCertificateCommands();
    byte[] caCertificateBytes = card.getCaCertificate();
    CaCertificateParserSpi caCertificateParser =
        (CaCertificateParserSpi)
            asymmetricCryptoSecuritySetting.getCaCertificateParser(caCertificateBytes[0]);
    CaCertificateSpi caCertificateSpi = caCertificateParser.parseCertificate(caCertificateBytes);

    return verifyAndAddCaCertificate(caCertificateSpi);
  }

  /**
   * Executes Get Data commands to retrieve the CA certificate from the card. The result will
   * available in the card image.
   */
  private void executeGetCaCertificateCommands() {
    List<Command> getCaCertificateCommands = new ArrayList<Command>(2);
    getCaCertificateCommands.add(
        new CommandGetDataCertificate(getTransactionContext(), getCommandContext(), false, true));
    getCaCertificateCommands.add(
        new CommandGetDataCertificate(getTransactionContext(), getCommandContext(), false, false));
    try {
      executeCardCommands(getCaCertificateCommands, originalChannelControl);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
  }

  /**
   * Parses the certificate, authenticate it against the parent certificate, which is expected to be
   * available in the settings' certificate store, and retrieves the CA certificate's public key.
   *
   * <p>Add the resulting CA certificate to the settings' store.
   *
   * @param caCertificateSpi The certificate to process.
   * @return The
   */
  private CaCertificateContentSpi verifyAndAddCaCertificate(CaCertificateSpi caCertificateSpi) {
    // search the current settings to see if the corresponding PCA certificate is available.
    CaCertificateContentSpi pcaCertificate =
        asymmetricCryptoSecuritySetting.getCertificate(
            caCertificateSpi.getIssuerPublicKeyReference());
    if (pcaCertificate == null) {
      // TODO throw exception
    }
    try {
      // invoke the PKI library to execute the cryptographic operations
      CaCertificateContentSpi caCertificate =
          caCertificateSpi.checkCertificateAndGetContent(pcaCertificate);
      asymmetricCryptoSecuritySetting.addCaCertificate((CaCertificate) caCertificateSpi);
      return caCertificate;
    } catch (CertificateException e) {
      // TODO change exception type
      throw new RuntimeException(
          "The extraction of the card public key from the card certificate failed", e);
    }
  }

  /**
   * Verifies the card certificate and get the card public key.
   *
   * @param cardCertificateSpi The card certificate to process.
   * @param caCertificate The parent CA certificate.
   * @return The card public key.
   */
  private CardPublicKeySpi extractAndVerifyCardPublicKey(
      CardCertificateSpi cardCertificateSpi, CaCertificateContentSpi caCertificate) {
    try {
      // invoke the PKI library to execute the cryptographic operations
      return cardCertificateSpi.checkCertificateAndGetPublicKey(
          caCertificate,
          new CardIdentifierApiAdapter(card.getDfName(), card.getCalypsoSerialNumberFull()));
    } catch (CertificateException e) {
      // TODO change exception type
      throw new RuntimeException(
          "The extraction of the card public key from the card certificate failed", e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public <E extends CardTransactionCryptoExtension> E getCryptoExtension(
      Class<E> cryptoExtensionClass) {
    // TODO Check if this is needed
    return (E) cryptoExtension;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public SecurePkiModeTransactionManager prepareOpenSecureSession() {
    prepareGetData(GetDataTag.CARD_CERTIFICATE);
    byte[] terminalChallenge = new byte[8];
    rand.nextBytes(terminalChallenge);
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
      commands.add(
          new CommandCloseSecureSession(getTransactionContext(), getCommandContext(), false));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    } finally {
      resetCommandContext();
      disablePreOpenMode();
    }
    return this;
  }

  /**
   * Adapter of {@link CardIdentifierApi}.
   *
   * <p>Provides methods to retrieve the AID and the serial number of a card.
   */
  static class CardIdentifierApiAdapter implements CardIdentifierApi {

    private final byte[] aid;
    private final byte[] serialNumber;

    /**
     * Constructs a new instance.
     *
     * @param aid The AID of the card.
     * @param serialNumber The serial number of the card.
     */
    CardIdentifierApiAdapter(byte[] aid, byte[] serialNumber) {
      this.aid = aid;
      this.serialNumber = serialNumber;
    }

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    @Override
    public byte[] getAid() {
      return aid;
    }

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    @Override
    public byte[] getSerialNumber() {
      return serialNumber;
    }
  }
}
