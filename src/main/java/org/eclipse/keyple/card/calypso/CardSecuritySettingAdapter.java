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
 * Implementation of {@link org.calypsonet.terminal.calypso.transaction.CardSecuritySetting}.
 *
 * @since 2.0
 */
final class CardSecuritySettingAdapter implements CardSecuritySetting {

  private CardReader samReader;
  private CalypsoSam calypsoSam;
  private boolean isMultipleSessionEnabled;
  private boolean isRatificationMechanismEnabled;
  private boolean isPinPlainTransmissionEnabled;
  private boolean isTransactionAuditEnabled;
  private boolean isSvLoadAndDebitLogEnabled;
  private boolean isSvNegativeBalanceAuthorized;
  private final Map<WriteAccessLevel, Map<Byte, Byte>> kifMap;
  private final Map<WriteAccessLevel, Byte> defaultKifMap;
  private final Map<WriteAccessLevel, Byte> defaultKvcMap;
  private final Set<Integer> authorizedSessionKeys;
  private final Set<Integer> authorizedSvKeys;

  private Byte pinCipheringKif;
  private Byte pinCipheringKvc;

  /**
   * (package-private)<br>
   * Constructor.
   */
  CardSecuritySettingAdapter() {
    kifMap = new EnumMap<WriteAccessLevel, Map<Byte, Byte>>(WriteAccessLevel.class);
    defaultKifMap = new EnumMap<WriteAccessLevel, Byte>(WriteAccessLevel.class);
    defaultKvcMap = new EnumMap<WriteAccessLevel, Byte>(WriteAccessLevel.class);
    authorizedSessionKeys = new HashSet<Integer>();
    authorizedSvKeys = new HashSet<Integer>();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSecuritySetting setSamResource(CardReader samReader, CalypsoSam calypsoSam) {

    Assert.getInstance().notNull(samReader, "samReader").notNull(calypsoSam, "calypsoSam");

    this.samReader = samReader;
    this.calypsoSam = calypsoSam;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSecuritySettingAdapter enableMultipleSession() {
    isMultipleSessionEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSecuritySettingAdapter enableRatificationMechanism() {
    isRatificationMechanismEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSecuritySettingAdapter enablePinPlainTransmission() {
    isPinPlainTransmissionEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSecuritySettingAdapter enableTransactionAudit() {
    isTransactionAuditEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSecuritySettingAdapter enableSvLoadAndDebitLog() {
    isSvLoadAndDebitLogEnabled = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSecuritySettingAdapter authorizeSvNegativeBalance() {
    isSvNegativeBalanceAuthorized = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSecuritySettingAdapter assignKif(
      WriteAccessLevel writeAccessLevel, byte kvc, byte kif) {

    Assert.getInstance().notNull(writeAccessLevel, "writeAccessLevel");

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
   * @since 2.0
   */
  @Override
  public CardSecuritySettingAdapter assignDefaultKif(WriteAccessLevel writeAccessLevel, byte kif) {

    Assert.getInstance().notNull(writeAccessLevel, "writeAccessLevel");

    defaultKifMap.put(writeAccessLevel, kif);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSecuritySettingAdapter assignDefaultKvc(WriteAccessLevel writeAccessLevel, byte kvc) {

    Assert.getInstance().notNull(writeAccessLevel, "writeAccessLevel");

    defaultKvcMap.put(writeAccessLevel, kvc);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSecuritySettingAdapter addAuthorizedSessionKey(byte kif, byte kvc) {
    authorizedSessionKeys.add(((kif << 8) & 0xff00) | (kvc & 0x00ff));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSecuritySettingAdapter addAuthorizedSvKey(byte kif, byte kvc) {
    authorizedSvKeys.add(((kif << 8) & 0xff00) | (kvc & 0x00ff));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSecuritySettingAdapter setPinCipheringKey(byte kif, byte kvc) {
    this.pinCipheringKif = kif;
    this.pinCipheringKvc = kvc;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardReader getSamReader() {
    return samReader;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoSam getCalypsoSam() {
    return calypsoSam;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public boolean isMultipleSessionEnabled() {
    return isMultipleSessionEnabled;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public boolean isRatificationMechanismEnabled() {
    return isRatificationMechanismEnabled;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public boolean isPinPlainTransmissionEnabled() {
    return isPinPlainTransmissionEnabled;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public boolean isTransactionAuditEnabled() {
    return isTransactionAuditEnabled;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public boolean isSvLoadAndDebitLogEnabled() {
    return isSvLoadAndDebitLogEnabled;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public boolean isSvNegativeBalanceAuthorized() {
    return isSvNegativeBalanceAuthorized;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public Byte getKif(WriteAccessLevel writeAccessLevel, byte kvc) {

    Assert.getInstance().notNull(writeAccessLevel, "writeAccessLevel");
    Map<Byte, Byte> map = kifMap.get(writeAccessLevel);
    if (map != null) {
      return map.get(kvc);
    } else {
      return null;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public Byte getDefaultKif(WriteAccessLevel writeAccessLevel) {
    return defaultKifMap.get(writeAccessLevel);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public Byte getDefaultKvc(WriteAccessLevel writeAccessLevel) {
    return defaultKvcMap.get(writeAccessLevel);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public boolean isSessionKeyAuthorized(Byte kif, Byte kvc) {
    if (kif == null || kvc == null) {
      return false;
    }
    if (authorizedSessionKeys.isEmpty()) {
      return true;
    }
    return authorizedSessionKeys.contains(((kif << 8) & 0xff00) | (kvc & 0x00ff));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public boolean isSvKeyAuthorized(Byte kif, Byte kvc) {
    if (kif == null || kvc == null) {
      return false;
    }
    if (authorizedSvKeys.isEmpty()) {
      return true;
    }
    return authorizedSvKeys.contains(((kif << 8) & 0xff00) | (kvc & 0x00ff));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public Byte getPinCipheringKif() {
    return pinCipheringKif;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public Byte getPinCipheringKvc() {
    return pinCipheringKvc;
  }
}
