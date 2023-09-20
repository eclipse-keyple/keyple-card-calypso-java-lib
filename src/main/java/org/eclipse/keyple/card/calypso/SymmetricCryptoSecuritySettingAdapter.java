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

import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.card.WriteAccessLevel;
import org.eclipse.keypop.calypso.card.transaction.SymmetricCryptoSecuritySetting;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoTransactionManagerFactorySpi;

/**
 * Adapter of {@link SymmetricCryptoSecuritySetting}.
 *
 * @since 2.3.1
 */
class SymmetricCryptoSecuritySettingAdapter implements SymmetricCryptoSecuritySetting {

  private static final String WRITE_ACCESS_LEVEL = "writeAccessLevel";

  private SymmetricCryptoTransactionManagerFactorySpi cryptoTransactionManagerFactorySpi;
  private boolean isMultipleSessionEnabled;
  private boolean isRatificationMechanismEnabled;
  private boolean isPinPlainTransmissionEnabled;
  private boolean isSvLoadAndDebitLogEnabled;
  private boolean isSvNegativeBalanceAuthorized;
  private boolean isReadOnSessionOpeningDisabled;

  private final Map<WriteAccessLevel, Map<Byte, Byte>> kifMap =
      new EnumMap<WriteAccessLevel, Map<Byte, Byte>>(WriteAccessLevel.class);

  private final Map<WriteAccessLevel, Byte> defaultKifMap =
      new EnumMap<WriteAccessLevel, Byte>(WriteAccessLevel.class);

  private final Map<WriteAccessLevel, Byte> defaultKvcMap =
      new EnumMap<WriteAccessLevel, Byte>(WriteAccessLevel.class);

  private final Set<Integer> authorizedSessionKeys = new HashSet<Integer>();
  private final Set<Integer> authorizedSvKeys = new HashSet<Integer>();

  private Byte pinVerificationCipheringKif;
  private Byte pinVerificationCipheringKvc;
  private Byte pinModificationCipheringKif;
  private Byte pinModificationCipheringKvc;

  SymmetricCryptoSecuritySettingAdapter(SymmetricCryptoTransactionManagerFactorySpi cryptoTransactionManagerFactorySpi) {
    this.cryptoTransactionManagerFactorySpi = cryptoTransactionManagerFactorySpi;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoSecuritySetting enableMultipleSession() {
    isMultipleSessionEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoSecuritySetting enableRatificationMechanism() {
    isRatificationMechanismEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoSecuritySetting enablePinPlainTransmission() {
    isPinPlainTransmissionEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoSecuritySetting enableSvLoadAndDebitLog() {
    isSvLoadAndDebitLogEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoSecuritySetting authorizeSvNegativeBalance() {
    isSvNegativeBalanceAuthorized = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public SymmetricCryptoSecuritySetting disableReadOnSessionOpening() {
    isReadOnSessionOpeningDisabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoSecuritySetting assignKif(
      WriteAccessLevel writeAccessLevel, byte kvc, byte kif) {
    Assert.getInstance().notNull(writeAccessLevel, WRITE_ACCESS_LEVEL);
    Map<Byte, Byte> map = kifMap.get(writeAccessLevel);
    if (map == null) {
      map = new HashMap<Byte, Byte>();
      kifMap.put(writeAccessLevel, map);
    }
    map.put(kvc, kif);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoSecuritySetting assignDefaultKif(
      WriteAccessLevel writeAccessLevel, byte kif) {
    Assert.getInstance().notNull(writeAccessLevel, WRITE_ACCESS_LEVEL);
    defaultKifMap.put(writeAccessLevel, kif);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoSecuritySetting assignDefaultKvc(
      WriteAccessLevel writeAccessLevel, byte kvc) {
    Assert.getInstance().notNull(writeAccessLevel, WRITE_ACCESS_LEVEL);
    defaultKvcMap.put(writeAccessLevel, kvc);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoSecuritySetting addAuthorizedSessionKey(byte kif, byte kvc) {
    authorizedSessionKeys.add(((kif << 8) & 0xff00) | (kvc & 0x00ff));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoSecuritySetting addAuthorizedSvKey(byte kif, byte kvc) {
    authorizedSvKeys.add(((kif << 8) & 0xff00) | (kvc & 0x00ff));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoSecuritySetting setPinVerificationCipheringKey(byte kif, byte kvc) {
    this.pinVerificationCipheringKif = kif;
    this.pinVerificationCipheringKvc = kvc;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SymmetricCryptoSecuritySetting setPinModificationCipheringKey(byte kif, byte kvc) {
    this.pinModificationCipheringKif = kif;
    this.pinModificationCipheringKvc = kvc;
    return this;
  }

  /**
   * Indicates if the multiple session mode is enabled.
   *
   * @return True if the multiple session mode is enabled.
   * @since 2.0.0
   */
  boolean isMultipleSessionEnabled() {
    return isMultipleSessionEnabled;
  }

  /**
   * Indicates if the ratification mechanism is enabled.
   *
   * @return True if the ratification mechanism is enabled.
   * @since 2.0.0
   */
  boolean isRatificationMechanismEnabled() {
    return isRatificationMechanismEnabled;
  }

  /**
   * Indicates if the transmission of the PIN in plain text is enabled.
   *
   * @return True if the transmission of the PIN in plain text is enabled.
   * @since 2.0.0
   */
  boolean isPinPlainTransmissionEnabled() {
    return isPinPlainTransmissionEnabled;
  }

  /**
   * Indicates if the retrieval of both load and debit log is enabled.
   *
   * @return True if the retrieval of both load and debit log is enabled.
   * @since 2.0.0
   */
  boolean isSvLoadAndDebitLogEnabled() {
    return isSvLoadAndDebitLogEnabled;
  }

  /**
   * Indicates if the SV balance is allowed to become negative.
   *
   * @return True if the retrieval of both load and debit log is enabled.
   * @since 2.0.0
   */
  boolean isSvNegativeBalanceAuthorized() {
    return isSvNegativeBalanceAuthorized;
  }

  /**
   * @return True if the auto-read optimization feature in the "Open Secure Session" command is
   *     disabled.
   * @since 2.3.2
   */
  boolean isReadOnSessionOpeningDisabled() {
    return isReadOnSessionOpeningDisabled;
  }

  /**
   * Gets the KIF value to use for the provided write access level and KVC value.
   *
   * @param writeAccessLevel The write access level.
   * @param kvc The KVC value.
   * @return Null if no KIF is available.
   * @throws IllegalArgumentException If the provided writeAccessLevel is null.
   * @since 2.0.0
   */
  Byte getKif(WriteAccessLevel writeAccessLevel, byte kvc) {
    Assert.getInstance().notNull(writeAccessLevel, WRITE_ACCESS_LEVEL);
    Map<Byte, Byte> map = kifMap.get(writeAccessLevel);
    if (map != null) {
      return map.get(kvc);
    } else {
      return null;
    }
  }

  /**
   * Gets the default KIF value for the provided write access level.
   *
   * @param writeAccessLevel The write access level.
   * @return Null if no KIF is available.
   * @throws IllegalArgumentException If the provided argument is null.
   * @since 2.0.0
   */
  Byte getDefaultKif(WriteAccessLevel writeAccessLevel) {
    return defaultKifMap.get(writeAccessLevel);
  }

  /**
   * Gets the default KVC value for the provided write access level.
   *
   * @param writeAccessLevel The write access level.
   * @return Null if no KVC is available.
   * @throws IllegalArgumentException If the provided argument is null.
   * @since 2.0.0
   */
  Byte getDefaultKvc(WriteAccessLevel writeAccessLevel) {
    return defaultKvcMap.get(writeAccessLevel);
  }

  /**
   * Indicates if the KIF/KVC pair is authorized for a session.
   *
   * @param kif The KIF value.
   * @param kvc The KVC value.
   * @return False if KIF or KVC is null or unauthorized.
   * @since 2.0.0
   */
  boolean isSessionKeyAuthorized(Byte kif, Byte kvc) {
    if (kif == null || kvc == null) {
      return false;
    }
    if (authorizedSessionKeys.isEmpty()) {
      return true;
    }
    return authorizedSessionKeys.contains(((kif << 8) & 0xff00) | (kvc & 0x00ff));
  }

  /**
   * Indicates if the KIF/KVC pair is authorized for a SV operation.
   *
   * @param kif The KIF value.
   * @param kvc The KVC value.
   * @return False if KIF or KVC is null or unauthorized.
   * @since 2.0.0
   */
  boolean isSvKeyAuthorized(Byte kif, Byte kvc) {
    if (kif == null || kvc == null) {
      return false;
    }
    if (authorizedSvKeys.isEmpty()) {
      return true;
    }
    return authorizedSvKeys.contains(((kif << 8) & 0xff00) | (kvc & 0x00ff));
  }

  /**
   * Gets the KIF value of the PIN verification ciphering key.
   *
   * @return Null if no KIF is available.
   * @since 2.0.0
   */
  Byte getPinVerificationCipheringKif() {
    return pinVerificationCipheringKif;
  }

  /**
   * Gets the KVC value of the PIN verification ciphering key.
   *
   * @return Null if no KVC is available.
   * @since 2.0.0
   */
  Byte getPinVerificationCipheringKvc() {
    return pinVerificationCipheringKvc;
  }

  /**
   * Gets the KIF value of the PIN modification ciphering key.
   *
   * @return Null if no KIF is available.
   * @since 2.0.0
   */
  Byte getPinModificationCipheringKif() {
    return pinModificationCipheringKif;
  }

  /**
   * Gets the KVC value of the PIN modification ciphering key.
   *
   * @return Null if no KVC is available.
   * @since 2.0.0
   */
  Byte getPinModificationCipheringKvc() {
    return pinModificationCipheringKvc;
  }

  SymmetricCryptoTransactionManagerFactorySpi getCryptoTransactionManagerFactorySpi() {
    return cryptoTransactionManagerFactorySpi;
  }

  Map<WriteAccessLevel, Map<Byte, Byte>> getKifMap() {
    return kifMap;
  }

  Map<WriteAccessLevel, Byte> getDefaultKifMap() {
    return defaultKifMap;
  }

  Map<WriteAccessLevel, Byte> getDefaultKvcMap() {
    return defaultKvcMap;
  }

  Set<Integer> getAuthorizedSessionKeys() {
    return authorizedSessionKeys;
  }

  Set<Integer> getAuthorizedSvKeys() {
    return authorizedSvKeys;
  }
}
