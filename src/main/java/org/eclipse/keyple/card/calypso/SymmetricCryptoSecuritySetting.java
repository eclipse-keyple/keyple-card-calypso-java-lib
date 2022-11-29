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

import org.calypsonet.terminal.calypso.WriteAccessLevel;

/**
 * Data to manage the security operations of a Calypso card transaction.
 *
 * @since x.y.z
 */
interface SymmetricCryptoSecuritySetting extends SecuritySetting<SymmetricCryptoSecuritySetting> {

  SymmetricCryptoSecuritySetting setCryptoTransactionManager(
      SymmetricCryptoTransactionManagerFactory cryptoTransactionManagerFactory);

  /**
   * Add an mutual authentication step at the beginning of the Secure Session when the card supports
   * the extended mode.
   *
   * <p>The default value is disabled.
   *
   * @return The current instance.
   * @since x.y.z
   */
  SymmetricCryptoSecuritySetting enableEarlyMutualAuthentication();

  /**
   * Enables the ratification mechanism to handle the early removal of the card preventing the
   * terminal from receiving the acknowledgement of the session closing.
   *
   * @return The current instance.
   * @since x.y.z
   */
  SymmetricCryptoSecuritySetting enableRatificationMechanism();

  /**
   * Enables the PIN transmission in plain text.
   *
   * <p>By default, the PIN is transmitted encrypted.
   *
   * @return The current instance.
   * @since x.y.z
   */
  SymmetricCryptoSecuritySetting enablePinPlainTransmission();

  /**
   * Enables the retrieval of both loading and debit log records.
   *
   * <p>The default value is false.
   *
   * @return The current instance.
   * @since x.y.z
   */
  SymmetricCryptoSecuritySetting enableSvLoadAndDebitLog();

  /**
   * Allows the SV balance to become negative.
   *
   * <p>The default value is false.
   *
   * @return The current instance.
   * @since x.y.z
   */
  SymmetricCryptoSecuritySetting authorizeSvNegativeBalance();

  /**
   * Force the use of regular mode for Secure Session and Stored Value operations.
   *
   * <p>The default value is false.
   *
   * @return The current instance.
   * @since x.y.z
   */
  SymmetricCryptoSecuritySetting forceRegularMode();

  /**
   * Defines for a given write access level the KIF value to use for cards that only provide KVC.
   *
   * @param writeAccessLevel The write access level.
   * @param kvc The card's KVC value.
   * @param kif The KIF value to use.
   * @return The current instance.
   * @throws IllegalArgumentException If the provided writeAccessLevel is null.
   * @since x.y.z
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
   * @since x.y.z
   */
  SymmetricCryptoSecuritySetting assignDefaultKif(WriteAccessLevel writeAccessLevel, byte kif);

  /**
   * Defines for a given write access level the KVC value to use for cards that do not provide KVC.
   *
   * @param writeAccessLevel The session level.
   * @param kvc The KVC to use.
   * @return The current instance.
   * @throws IllegalArgumentException If the provided writeAccessLevel is null.
   * @since x.y.z
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
   * @since x.y.z
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
   * @since x.y.z
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
   * @since x.y.z
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
   * @since x.y.z
   */
  SymmetricCryptoSecuritySetting setPinModificationCipheringKey(byte kif, byte kvc);
}
