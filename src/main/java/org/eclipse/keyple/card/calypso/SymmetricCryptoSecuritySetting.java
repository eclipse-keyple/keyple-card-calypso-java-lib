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

import org.eclipse.keypop.calypso.card.WriteAccessLevel;

/**
 * Data to manage the security operations of a Calypso card transaction.
 *
 * @since 2.3.1
 */
interface SymmetricCryptoSecuritySetting {

  SymmetricCryptoSecuritySetting setCryptoTransactionManager(
      SymmetricCryptoTransactionManagerFactory cryptoTransactionManagerFactory);

  /**
   * Enables multiple session mode to allow more changes to the card than the session buffer can
   * handle.
   *
   * @return The current instance.
   * @since 2.3.1
   */
  SymmetricCryptoSecuritySetting enableMultipleSession();

  /**
   * Enables the ratification mechanism to handle the early removal of the card preventing the
   * terminal from receiving the acknowledgement of the session closing.
   *
   * @return The current instance.
   * @since 2.3.1
   */
  SymmetricCryptoSecuritySetting enableRatificationMechanism();

  /**
   * Enables the PIN transmission in plain text.
   *
   * <p>By default, the PIN is transmitted encrypted.
   *
   * @return The current instance.
   * @since 2.3.1
   */
  SymmetricCryptoSecuritySetting enablePinPlainTransmission();

  /**
   * Enables the retrieval of both loading and debit log records.
   *
   * <p>The default value is false.
   *
   * @return The current instance.
   * @since 2.3.1
   */
  SymmetricCryptoSecuritySetting enableSvLoadAndDebitLog();

  /**
   * Allows the SV balance to become negative.
   *
   * <p>The default value is false.
   *
   * @return The current instance.
   * @since 2.3.1
   */
  SymmetricCryptoSecuritySetting authorizeSvNegativeBalance();

  /**
   * Defines for a given write access level the KIF value to use for cards that only provide KVC.
   *
   * @param writeAccessLevel The write access level.
   * @param kvc The card's KVC value.
   * @param kif The KIF value to use.
   * @return The current instance.
   * @throws IllegalArgumentException If the provided writeAccessLevel is null.
   * @since 2.3.1
   */
  SymmetricCryptoSecuritySetting assignKif(WriteAccessLevel writeAccessLevel, byte kvc, byte kif);

  /**
   * Defines for a given write access level the default KIF value to use when it could not be
   * determined by any other means.
   *
   * @param writeAccessLevel The write access level.
   * @param kif The KIF value to use.
   * @return The current instance.
   * @throws IllegalArgumentException If the provided writeAccessLevel is null.
   * @since 2.3.1
   */
  SymmetricCryptoSecuritySetting assignDefaultKif(WriteAccessLevel writeAccessLevel, byte kif);

  /**
   * Defines for a given write access level the KVC value to use for cards that do not provide KVC.
   *
   * @param writeAccessLevel The session level.
   * @param kvc The KVC to use.
   * @return The current instance.
   * @throws IllegalArgumentException If the provided writeAccessLevel is null.
   * @since 2.3.1
   */
  SymmetricCryptoSecuritySetting assignDefaultKvc(WriteAccessLevel writeAccessLevel, byte kvc);

  /**
   * Adds an authorized session key defined by its KIF and KVC values.
   *
   * <p>By default, all keys are accepted. <br>
   * If at least one key is added using this method, then only authorized keys will be accepted.
   *
   * @param kif The KIF value.
   * @param kvc The KVC value.
   * @return The current instance.
   * @since 2.3.1
   */
  SymmetricCryptoSecuritySetting addAuthorizedSessionKey(byte kif, byte kvc);

  /**
   * Adds an authorized Stored Value key defined by its KIF and KVC values.
   *
   * <p>By default, all keys are accepted. <br>
   * If at least one key is added using this method, then only authorized keys will be accepted.
   *
   * @param kif The KIF value.
   * @param kvc The KVC value.
   * @return The current instance.
   * @since 2.3.1
   */
  SymmetricCryptoSecuritySetting addAuthorizedSvKey(byte kif, byte kvc);

  /**
   * Sets the KIF/KVC pair of the PIN verification ciphering key.
   *
   * <p>The default value for both KIF and KVC is 0.
   *
   * @param kif The KIF value.
   * @param kvc The KVC value.
   * @return The current instance.
   * @since 2.3.1
   */
  SymmetricCryptoSecuritySetting setPinVerificationCipheringKey(byte kif, byte kvc);

  /**
   * Sets the KIF/KVC pair of the PIN modification ciphering key.
   *
   * <p>The default value for both KIF and KVC is 0.
   *
   * @param kif The KIF value.
   * @param kvc The KVC value.
   * @return The current instance.
   * @since 2.3.1
   */
  SymmetricCryptoSecuritySetting setPinModificationCipheringKey(byte kif, byte kvc);
}
