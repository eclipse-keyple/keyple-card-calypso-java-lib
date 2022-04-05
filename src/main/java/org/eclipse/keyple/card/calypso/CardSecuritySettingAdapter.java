/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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

import java.util.*;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.transaction.CardSecuritySetting;
import org.calypsonet.terminal.reader.CardReader;
import org.eclipse.keyple.core.util.Assert;

/**
 * (package-private)<br>
 * Implementation of {@link CardSecuritySetting}.
 *
 * @since 2.0.0
 */
final class CardSecuritySettingAdapter extends CommonSecuritySettingAdapter<CardSecuritySetting>
    implements CardSecuritySetting {

  private static final String WRITE_ACCESS_LEVEL = "writeAccessLevel";

  private boolean isMultipleSessionEnabled;
  private boolean isRatificationMechanismEnabled;
  private boolean isPinPlainTransmissionEnabled;
  private boolean isSvLoadAndDebitLogEnabled;
  private boolean isSvNegativeBalanceAuthorized;

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

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated Use {@link #setControlSamResource(CardReader, CalypsoSam)} instead.
   */
  @Override
  @Deprecated
  public CardSecuritySetting setSamResource(CardReader samReader, CalypsoSam calypsoSam) {
    return setControlSamResource(samReader, calypsoSam);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSecuritySettingAdapter enableMultipleSession() {
    isMultipleSessionEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSecuritySettingAdapter enableRatificationMechanism() {
    isRatificationMechanismEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSecuritySettingAdapter enablePinPlainTransmission() {
    isPinPlainTransmissionEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSecuritySettingAdapter enableSvLoadAndDebitLog() {
    isSvLoadAndDebitLogEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSecuritySettingAdapter authorizeSvNegativeBalance() {
    isSvNegativeBalanceAuthorized = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSecuritySettingAdapter assignKif(
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
   * @since 2.0.0
   */
  @Override
  public CardSecuritySettingAdapter assignDefaultKif(WriteAccessLevel writeAccessLevel, byte kif) {
    Assert.getInstance().notNull(writeAccessLevel, WRITE_ACCESS_LEVEL);
    defaultKifMap.put(writeAccessLevel, kif);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSecuritySettingAdapter assignDefaultKvc(WriteAccessLevel writeAccessLevel, byte kvc) {
    Assert.getInstance().notNull(writeAccessLevel, WRITE_ACCESS_LEVEL);
    defaultKvcMap.put(writeAccessLevel, kvc);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSecuritySettingAdapter addAuthorizedSessionKey(byte kif, byte kvc) {
    authorizedSessionKeys.add(((kif << 8) & 0xff00) | (kvc & 0x00ff));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSecuritySettingAdapter addAuthorizedSvKey(byte kif, byte kvc) {
    authorizedSvKeys.add(((kif << 8) & 0xff00) | (kvc & 0x00ff));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSecuritySettingAdapter setPinVerificationCipheringKey(byte kif, byte kvc) {
    this.pinVerificationCipheringKif = kif;
    this.pinVerificationCipheringKvc = kvc;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSecuritySettingAdapter setPinModificationCipheringKey(byte kif, byte kvc) {
    this.pinModificationCipheringKif = kif;
    this.pinModificationCipheringKvc = kvc;
    return this;
  }

  /**
   * (package-private)<br>
   * Indicates if the multiple session mode is enabled.
   *
   * @return True if the multiple session mode is enabled.
   * @since 2.0.0
   */
  boolean isMultipleSessionEnabled() {
    return isMultipleSessionEnabled;
  }

  /**
   * (package-private)<br>
   * Indicates if the ratification mechanism is enabled.
   *
   * @return True if the ratification mechanism is enabled.
   * @since 2.0.0
   */
  boolean isRatificationMechanismEnabled() {
    return isRatificationMechanismEnabled;
  }

  /**
   * (package-private)<br>
   * Indicates if the transmission of the PIN in plain text is enabled.
   *
   * @return True if the transmission of the PIN in plain text is enabled.
   * @since 2.0.0
   */
  boolean isPinPlainTransmissionEnabled() {
    return isPinPlainTransmissionEnabled;
  }

  /**
   * (package-private)<br>
   * Indicates if the retrieval of both load and debit log is enabled.
   *
   * @return True if the retrieval of both load and debit log is enabled.
   * @since 2.0.0
   */
  boolean isSvLoadAndDebitLogEnabled() {
    return isSvLoadAndDebitLogEnabled;
  }

  /**
   * (package-private)<br>
   * Indicates if the SV balance is allowed to become negative.
   *
   * @return True if the retrieval of both load and debit log is enabled.
   * @since 2.0.0
   */
  boolean isSvNegativeBalanceAuthorized() {
    return isSvNegativeBalanceAuthorized;
  }

  /**
   * (package-private)<br>
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
   * (package-private)<br>
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
   * (package-private)<br>
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
   * (package-private)<br>
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
   * (package-private)<br>
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
   * (package-private)<br>
   * Gets the KIF value of the PIN verification ciphering key.
   *
   * @return Null if no KIF is available.
   * @since 2.0.0
   */
  Byte getPinVerificationCipheringKif() {
    return pinVerificationCipheringKif;
  }

  /**
   * (package-private)<br>
   * Gets the KVC value of the PIN verification ciphering key.
   *
   * @return Null if no KVC is available.
   * @since 2.0.0
   */
  Byte getPinVerificationCipheringKvc() {
    return pinVerificationCipheringKvc;
  }

  /**
   * (package-private)<br>
   * Gets the KIF value of the PIN modification ciphering key.
   *
   * @return Null if no KIF is available.
   * @since 2.0.0
   */
  Byte getPinModificationCipheringKif() {
    return pinModificationCipheringKif;
  }

  /**
   * (package-private)<br>
   * Gets the KVC value of the PIN modification ciphering key.
   *
   * @return Null if no KVC is available.
   * @since 2.0.0
   */
  Byte getPinModificationCipheringKvc() {
    return pinModificationCipheringKvc;
  }
}
