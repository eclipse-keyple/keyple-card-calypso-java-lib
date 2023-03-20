/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://calypsonet.org/
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

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.card.ApduResponseApi;

/**
 * Superclass for all card commands.
 *
 * <p>It provides the generic getters to retrieve:
 *
 * <ul>
 *   <li>the card command reference,
 *   <li>the name of the command,
 *   <li>the built {@link org.calypsonet.terminal.card.spi.ApduRequestSpi},
 *   <li>the parsed {@link org.calypsonet.terminal.card.ApduResponseApi}.
 * </ul>
 *
 * @since 2.0.1
 */
abstract class CardCommand {

  static final byte[] APDU_RESPONSE_9000 = new byte[] {(byte) 0x90, 0x00};

  /**
   * This Map stores expected status that could be by default initialized with sw1=90 and sw2=00
   * (Success)
   *
   * @since 2.0.1
   */
  static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    HashMap<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>();
    m.put(0x9000, new StatusProperties("Success"));
    STATUS_TABLE = m;
  }

  private final CardCommandRef commandRef;
  private int le;
  private transient String name; // NOSONAR
  private ApduRequestAdapter apduRequest;
  private ApduResponseApi apduResponse;
  private CalypsoCardAdapter calypsoCard;
  private final TransactionContextDto transactionContext;
  private final CommandContextDto commandContext;
  private transient boolean isCryptoServiceSynchronized; // NOSONAR

  /**
   * Constructor dedicated for the building of referenced Calypso commands
   *
   * @param commandRef A command reference from the Calypso command table.
   * @param le The value of the LE field.
   * @param calypsoCard The Calypso card (it may be null if the card selection has not yet been
   *     made).
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command
   * @since 2.0.1
   */
  CardCommand(
      CardCommandRef commandRef,
      int le,
      CalypsoCardAdapter calypsoCard,
      TransactionContextDto transactionContext,
      CommandContextDto commandContext) {
    this.commandRef = commandRef;
    this.name = commandRef.getName();
    this.le = le;
    this.calypsoCard = calypsoCard;
    this.transactionContext = transactionContext;
    this.commandContext = commandContext;
  }

  /**
   * Indicates if the session buffer is used when executing this command.
   *
   * <p>Allows the management of the overflow of this buffer.
   *
   * @return True if this command uses the session buffer
   * @since 2.0.1
   */
  abstract boolean isSessionBufferUsed();

  /**
   * Appends a string to the current name.
   *
   * <p>The sub name completes the name of the current command. This method must therefore only be
   * invoked conditionally (log level &gt;= debug).
   *
   * @param subName The string to append.
   * @throws NullPointerException If the request is not set.
   * @since 2.0.1
   */
  final void addSubName(String subName) {
    this.name = this.name + " - " + subName;
    this.apduRequest.setInfo(this.name);
  }

  /**
   * Returns the current command identification
   *
   * @return A not null reference.
   * @since 2.0.1
   */
  final CardCommandRef getCommandRef() {
    return commandRef;
  }

  /**
   * Gets the name of this APDU command.
   *
   * @return A not empty string.
   * @since 2.0.1
   */
  final String getName() {
    return this.name;
  }

  /**
   * Sets the command {@link ApduRequestAdapter}.
   *
   * @param apduRequest The APDU request.
   * @since 2.0.1
   */
  final void setApduRequest(ApduRequestAdapter apduRequest) {
    this.apduRequest = apduRequest;
    this.apduRequest.setInfo(this.name);
  }

  /**
   * Gets the {@link ApduRequestAdapter}.
   *
   * @return Null if the request is not set.
   * @since 2.0.1
   */
  final ApduRequestAdapter getApduRequest() {
    return apduRequest;
  }

  /**
   * Gets {@link ApduResponseApi}
   *
   * @return Null if the response is not set.
   * @since 2.0.1
   */
  final ApduResponseApi getApduResponse() {
    return apduResponse;
  }

  /**
   * Returns the Calypso card.
   *
   * @return Null if the card selection has not yet been made.
   * @since 2.2.3
   */
  final CalypsoCardAdapter getCalypsoCard() {
    return calypsoCard;
  }

  /**
   * Returns the transaction context.
   *
   * @return Null if not defined (selection process) or for legacy use (deprecated methods).
   * @since 2.3.2
   */
  final TransactionContextDto getTransactionContext() {
    return transactionContext;
  }

  /**
   * Returns the command context.
   *
   * @return Null if not defined (selection process) or for legacy use (deprecated methods).
   * @since 2.3.2
   */
  final CommandContextDto getCommandContext() {
    return commandContext;
  }

  /**
   * @param le The value of the LE field.
   * @since 2.3.2
   */
  final void setLe(int le) {
    this.le = le;
  }

  /**
   * Returns the value of the LE.
   *
   * @return 0 if LE is not set.
   * @since 2.3.2
   */
  final int getLe() {
    return le;
  }

  /**
   * Notifies that the crypto service has been synchronized.
   *
   * @since 2.3.2
   */
  final void confirmCryptoServiceSuccessfullySynchronized() {
    isCryptoServiceSynchronized = true;
  }

  /**
   * @return "true" if the post-processing is already done.
   * @since 2.3.2
   */
  final boolean isCryptoServiceSynchronized() {
    return isCryptoServiceSynchronized;
  }

  /**
   * Finalize the construction of the APDU request if needed.
   *
   * @since 2.3.2
   */
  abstract void finalizeRequest();

  /**
   * @return "true" if the crypto service is required to finalize the construction of the request.
   * @since 2.3.2
   */
  abstract boolean isCryptoServiceRequiredToFinalizeRequest();

  /**
   * Attempts to synchronize the crypto service before executing the finalized command on the card
   * and returns "true" in any of the following cases:
   *
   * <ul>
   *   <li>the crypto service is not involved in the process
   *   <li>the crypto service has been correctly synchronized
   *   <li>the crypto service has already been synchronized
   * </ul>
   *
   * @return "false" if the crypto service could not be synchronized before transmitting the
   *     commands to the card.
   * @since 2.3.2
   */
  abstract boolean synchronizeCryptoServiceBeforeCardProcessing();

  /**
   * Parses the APDU response, updates the card image and synchronize the crypto service if it is
   * involved in the process.
   *
   * @param apduResponse The APDU response.
   * @throws CardCommandException if status is not successful or if the length of the response is
   *     not equal to the LE field in the request.
   * @since 2.3.2
   */
  abstract void parseResponse(ApduResponseApi apduResponse) throws CardCommandException;

  /**
   * Updates the terminal session MAC using the parsed APDU response if the encryption is not
   * active. If encryption is enabled, then the session MAC has already been updated during
   * decryption.
   *
   * @since 2.3.2
   */
  final void updateTerminalSessionMacIfNeeded() {
    updateTerminalSessionMacIfNeeded(apduResponse.getApdu());
  }

  /**
   * Updates the terminal session MAC using the provided APDU response.
   *
   * @param apduResponse The APDU response to use.
   * @since 2.3.2
   */
  final void updateTerminalSessionMacIfNeeded(byte[] apduResponse) {
    if (isCryptoServiceSynchronized) {
      return;
    }
    if (commandContext.isSecureSessionOpen()) {
      try {
        transactionContext
            .getSymmetricCryptoTransactionManagerSpi()
            .updateTerminalSessionMac(apduRequest.getApdu());
        transactionContext
            .getSymmetricCryptoTransactionManagerSpi()
            .updateTerminalSessionMac(apduResponse);
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      } catch (SymmetricCryptoIOException e) {
        throw (RuntimeException) e.getCause();
      }
    }
    isCryptoServiceSynchronized = true;
  }

  /**
   * Encrypts the APDU request using the crypto service and updates the terminal session MAC if the
   * encryption is active.
   *
   * @since 2.3.2
   */
  final void encryptRequestAndUpdateTerminalSessionMacIfNeeded() {
    if (commandContext.isEncryptionActive()) {
      try {
        apduRequest.setApdu(
            transactionContext
                .getSymmetricCryptoTransactionManagerSpi()
                .updateTerminalSessionMac(apduRequest.getApdu()));
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      } catch (SymmetricCryptoIOException e) {
        throw (RuntimeException) e.getCause();
      }
    }
  }

  /**
   * Decrypts the provided APDU response using the crypto service and updates the terminal session
   * MAC if the encryption is active.
   *
   * @param apduResponse The APDU response to update.
   * @since 2.3.2
   */
  final void decryptResponseAndUpdateTerminalSessionMacIfNeeded(ApduResponseApi apduResponse) {
    if (commandContext.isEncryptionActive()) {
      try {
        byte[] decryptedApdu =
            transactionContext
                .getSymmetricCryptoTransactionManagerSpi()
                .updateTerminalSessionMac(apduResponse.getApdu());
        System.arraycopy(decryptedApdu, 0, apduResponse.getApdu(), 0, decryptedApdu.length);
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      } catch (SymmetricCryptoIOException e) {
        throw (RuntimeException) e.getCause();
      }
      isCryptoServiceSynchronized = true;
    }
  }

  /**
   * Parses the response and checks the status word.
   *
   * @param apduResponse The APDU response.
   * @throws CardCommandException If status is not successful or if the length of the response is
   *     not equal to the LE field in the request.
   * @since 2.0.1
   */
  void setApduResponseAndCheckStatus(ApduResponseApi apduResponse) throws CardCommandException {
    this.apduResponse = apduResponse;
    checkStatus();
  }

  /**
   * Parses the response and checks the status word in "best effort" mode.
   *
   * <p>Do not throw exception for "file not found" and "record not found" errors outside a secure
   * session.
   *
   * @param apduResponse The APDU response.
   * @return "false" in case of "best effort" mode and a "file not found" or a "record not found"
   *     error occurs. In this case, the process must be stopped.
   * @throws CardCommandException If status is not successful and a secure session is open or the SW
   *     is different of 6A82h and 6A83h, or if the length of the response is not equal to the LE
   *     field in the request.
   * @since 2.3.2
   */
  final boolean setApduResponseAndCheckStatusInBestEffortMode(ApduResponseApi apduResponse)
      throws CardCommandException {
    this.apduResponse = apduResponse;
    try {
      checkStatus();
    } catch (CardDataAccessException e) {
      if (getCommandContext().isSecureSessionOpen()
          || (apduResponse.getStatusWord() != 0x6A82 && apduResponse.getStatusWord() != 0x6A83)) {
        throw e;
      }
      return false;
    }
    return true;
  }

  /**
   * Sets the Calypso card and invoke the {@link #setApduResponseAndCheckStatus(ApduResponseApi)}
   * method.
   *
   * @since 2.2.3
   */
  final void setApduResponseAndCheckStatus(
      ApduResponseApi apduResponse, CalypsoCardAdapter calypsoCard) throws CardCommandException {
    this.calypsoCard = calypsoCard;
    setApduResponseAndCheckStatus(apduResponse);
  }

  /**
   * Returns the internal status table
   *
   * @return A not null reference
   * @since 2.0.1
   */
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * @return The properties of the result.
   * @throws NullPointerException If the response is not set.
   */
  private StatusProperties getStatusWordProperties() {
    return getStatusTable().get(apduResponse.getStatusWord());
  }

  /**
   * Gets true if the status is successful from the statusTable according to the current status code
   * and if the length of the response is equal to the LE field in the request.
   *
   * @return A value
   * @since 2.0.1
   */
  final boolean isSuccessful() {
    StatusProperties props = getStatusWordProperties();
    return props != null
        && props.isSuccessful()
        && (le == 0 || apduResponse.getDataOut().length == le); // CL-CSS-RESPLE.1
  }

  /**
   * This method check the status word and if the length of the response is equal to the LE field in
   * the request.<br>
   * If status word is not referenced, then status is considered unsuccessful.
   *
   * @throws CardCommandException if status is not successful or if the length of the response is
   *     not equal to the LE field in the request.
   */
  private void checkStatus() throws CardCommandException {

    StatusProperties props = getStatusWordProperties();
    if (props != null && props.isSuccessful()) {
      // SW is successful, then check the response length (CL-CSS-RESPLE.1)
      if (le != 0 && apduResponse.getDataOut().length != le) {
        throw new CardUnexpectedResponseLengthException(
            String.format(
                "Incorrect APDU response length (expected: %d, actual: %d)",
                le, apduResponse.getDataOut().length),
            commandRef);
      }
      // SW and response length are correct.
      return;
    }
    // status word is not referenced, or not successful.

    // exception class
    Class<? extends CardCommandException> exceptionClass =
        props != null ? props.getExceptionClass() : null;

    // message
    String message = props != null ? props.getInformation() : "Unknown status";

    // Throw the exception
    throw buildCommandException(exceptionClass, message);
  }

  /**
   * Builds a specific APDU command exception.
   *
   * @param exceptionClass the exception class.
   * @param message The message.
   * @return A not null reference.
   * @since 2.0.1
   */
  private CardCommandException buildCommandException(
      Class<? extends CardCommandException> exceptionClass, String message) {
    CardCommandException e;
    if (exceptionClass == CardAccessForbiddenException.class) {
      e = new CardAccessForbiddenException(message, commandRef);
    } else if (exceptionClass == CardDataAccessException.class) {
      e = new CardDataAccessException(message, commandRef);
    } else if (exceptionClass == CardDataOutOfBoundsException.class) {
      e = new CardDataOutOfBoundsException(message, commandRef);
    } else if (exceptionClass == CardIllegalArgumentException.class) {
      e = new CardIllegalArgumentException(message, commandRef);
    } else if (exceptionClass == CardIllegalParameterException.class) {
      e = new CardIllegalParameterException(message, commandRef);
    } else if (exceptionClass == CardPinException.class) {
      e = new CardPinException(message, commandRef);
    } else if (exceptionClass == CardSecurityContextException.class) {
      e = new CardSecurityContextException(message, commandRef);
    } else if (exceptionClass == CardSecurityDataException.class) {
      e = new CardSecurityDataException(message, commandRef);
    } else if (exceptionClass == CardSessionBufferOverflowException.class) {
      e = new CardSessionBufferOverflowException(message, commandRef);
    } else if (exceptionClass == CardTerminatedException.class) {
      e = new CardTerminatedException(message, commandRef);
    } else {
      e = new CardUnknownStatusException(message, commandRef);
    }
    return e;
  }

  /**
   * This internal class provides status word properties
   *
   * @since 2.0.1
   */
  static class StatusProperties {

    private final String information;

    private final boolean successful;

    private final Class<? extends CardCommandException> exceptionClass;

    /**
     * Creates a successful status.
     *
     * @param information the status information.
     * @since 2.0.1
     */
    StatusProperties(String information) {
      this.information = information;
      this.successful = true;
      this.exceptionClass = null;
    }

    /**
     * Creates an error status.<br>
     * If {@code exceptionClass} is null, then a successful status is created.
     *
     * @param information the status information.
     * @param exceptionClass the associated exception class.
     * @since 2.0.1
     */
    StatusProperties(String information, Class<? extends CardCommandException> exceptionClass) {
      this.information = information;
      this.successful = exceptionClass == null;
      this.exceptionClass = exceptionClass;
    }

    /**
     * Gets information
     *
     * @return A nullable reference
     * @since 2.0.1
     */
    String getInformation() {
      return information;
    }

    /**
     * Gets successful indicator
     *
     * @return The successful indicator
     * @since 2.0.1
     */
    boolean isSuccessful() {
      return successful;
    }

    /**
     * Gets Exception Class
     *
     * @return A nullable reference
     * @since 2.0.1
     */
    Class<? extends CardCommandException> getExceptionClass() {
      return exceptionClass;
    }
  }
}
