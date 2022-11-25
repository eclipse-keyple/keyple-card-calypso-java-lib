/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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

/**
 * Calypso card symmetric key cryptography service.
 *
 * <p>This interface defines the API needed by a terminal to perform the cryptographic operations
 * required by a Calypso card when using symmetric keys.
 *
 * @since x.y.z
 */
interface SymmetricCryptoTransactionManagerSpi {

  /**
   * Initializes the crypto service context for operating a Secure Session with a card and gets the
   * terminal challenge.
   *
   * @return The terminal challenge.
   * @since x.y.z
   */
  byte[] initTerminalSecureSessionContext()
      throws SymmetricCryptoException, SymmetricCryptoIOException;

  /**
   * Stores the data needed to initialize the session MAC computation for a Secure Session.
   *
   * @param openSecureSessionDataOut The data out from the card Open Secure Session command.
   * @param kif The card KIF.
   * @param kvc The card KVC.
   * @since x.y.z
   */
  void initTerminalSessionMac(byte[] openSecureSessionDataOut, byte kif, byte kvc)
      throws SymmetricCryptoException, SymmetricCryptoIOException;

  /**
   * Updates the digest computation with data sent or received from the card.
   *
   * <p>Returns encrypted/decrypted data when the encryption is active.
   *
   * @param cardApdu A byte array containing either the input or output data of a card command APDU.
   * @return null if the encryption is not activate, either the ciphered or deciphered command data
   *     if the encryption is active.
   * @since x.y.z
   */
  byte[] updateTerminalSessionMac(byte[] cardApdu)
      throws SymmetricCryptoException, SymmetricCryptoIOException;

  /**
   * Finalizes the digest computation and returns the terminal part of the session MAC.
   *
   * @return A byte array containing the terminal session MAC.
   * @since x.y.z
   */
  byte[] finalizeTerminalSessionMac() throws SymmetricCryptoException, SymmetricCryptoIOException;

  /**
   * Generate the terminal part of the session MAC used for an early mutual authentication.
   *
   * @return A byte array containing the terminal session MAC.
   * @since x.y.z
   */
  byte[] generateTerminalSessionMac() throws SymmetricCryptoException, SymmetricCryptoIOException;

  /**
   * Activate the encryption/decryption of the data sent/received during the secure session.
   *
   * @since x.y.z
   */
  void activateEncryption() throws SymmetricCryptoException, SymmetricCryptoIOException;

  /**
   * Deactivate the encryption/decryption of the data sent/received during the secure session.
   *
   * @since x.y.z
   */
  void deactivateEncryption() throws SymmetricCryptoException, SymmetricCryptoIOException;

  /**
   * Verifies the card part of the session MAC finalizing the mutual authentication process.
   *
   * @param cardSessionMac A byte array containing the card session MAC.
   * @return true if the card session MAC is validated.
   * @since x.y.z
   */
  boolean verifyCardSessionMac(byte[] cardSessionMac)
      throws SymmetricCryptoException, SymmetricCryptoIOException;

  /**
   * Computes the needed data to operate SV card commands.
   *
   * @param data The data involved in the preparation of an SV Reload/Debit/Undebit command.
   * @since x.y.z
   */
  void computeSvCommandSecurityData(SvCommandSecurityDataApi data)
      throws SymmetricCryptoException, SymmetricCryptoIOException;

  /**
   * Verifies the SV card MAC.
   *
   * @param cardSvMac A byte array containing the card SV MAC.
   * @return true if the card SV MAC is validated.
   * @since x.y.z
   */
  boolean verifyCardSvMac(byte[] cardSvMac)
      throws SymmetricCryptoException, SymmetricCryptoIOException;

  /**
   * Computes a block of encrypted data to be sent to the card for an enciphered PIN presentation.
   *
   * <p>Note: the <code>kif</code> and <code>kvc</code> parameters are ignored when PIN verification
   * is performed within a Secure Session.
   *
   * @param cardChallenge A byte array containing the card challenge.
   * @param pin A byte array containing the 4-byte PIN value.
   * @param kif The PIN encryption key KIF.
   * @param kvc The PIN encryption key KVC.
   * @return A byte array containing the encrypted data block to sent to the card.
   * @since x.y.z
   */
  byte[] cipherPinForPresentation(byte[] cardChallenge, byte[] pin, Byte kif, Byte kvc)
      throws SymmetricCryptoException, SymmetricCryptoIOException;

  /**
   * Computes a block of encrypted data to be sent to the card for a PIN modification.
   *
   * <p>Note: the <code>kif</code> and <code>kvc</code> parameters are ignored when PIN modification
   * is performed within a Secure Session.
   *
   * @param cardChallenge A byte array containing the card challenge.
   * @param currentPin A byte array containing the 4-byte current PIN value.
   * @param newPin A byte array containing the 4-byte new PIN value.
   * @param kif The PIN encryption key KIF.
   * @param kvc The PIN encryption key KVC.
   * @return A byte array containing the encrypted data block to sent to the card.
   * @since x.y.z
   */
  byte[] cipherPinForModification(
      byte[] cardChallenge, byte[] currentPin, byte[] newPin, Byte kif, Byte kvc)
      throws SymmetricCryptoException, SymmetricCryptoIOException;

  /**
   * Generates an encrypted key data block for loading a key into a card.
   *
   * @param cardChallenge A byte array containing the card challenge.
   * @param issuerKeyKif The issuer key KIF.
   * @param issuerKeyKvc The issuer key KVC.
   * @param targetKeyKif The target key KIF.
   * @param targetKeyKvc The target key KVC.
   * @return A byte array containing the encrypted data block to sent to the card.
   * @since x.y.z
   */
  byte[] generateCipheredCardKey(
      byte[] cardChallenge,
      byte issuerKeyKif,
      byte issuerKeyKvc,
      byte targetKeyKif,
      byte targetKeyKvc)
      throws SymmetricCryptoException, SymmetricCryptoIOException;
}
