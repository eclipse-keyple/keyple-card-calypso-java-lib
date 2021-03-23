/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.calypso;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.eclipse.keyple.calypso.smartcard.sam.CalypsoSamSmartCard;
import org.eclipse.keyple.calypso.transaction.PoSecuritySettings;
import org.eclipse.keyple.calypso.transaction.PoTransaction;
import org.eclipse.keyple.core.service.selection.CardResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 *
 * @since 2.0
 */
class PoSecuritySettingsAdapter implements PoSecuritySettings {

  private static final Logger logger = LoggerFactory.getLogger(PoSecuritySettingsAdapter.class);

  private CardResource<CalypsoSamSmartCard> samResource;
  private final List<Byte> authorizedKvcList;
  private final EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKIFs;
  private final EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKVCs;
  private final EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKeyRecordNumbers;

  private PoTransaction.SessionSetting.ModificationMode sessionModificationMode;
  private PoTransaction.SessionSetting.RatificationMode ratificationMode;
  private PoTransaction.PinTransmissionMode pinTransmissionMode;
  private KeyReference defaultPinCipheringKey;
  private PoTransaction.SvSettings.LogRead svGetLogReadMode;
  private PoTransaction.SvSettings.NegativeBalance svNegativeBalance;

  /**
   * (package-private)<br>
   * Creates an
   *
   * @since 2.0
   */
  PoSecuritySettingsAdapter() {
    // TODO check if we need thread safe collections here
    authorizedKvcList = new ArrayList<Byte>();
    defaultKIFs =
        new EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte>(
            PoTransaction.SessionSetting.AccessLevel.class);
    defaultKVCs =
        new EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte>(
            PoTransaction.SessionSetting.AccessLevel.class);
    defaultKeyRecordNumbers =
        new EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte>(
            PoTransaction.SessionSetting.AccessLevel.class);
  }

  /**
   * (package-private) Sets the SAM resource.
   *
   * @param samResource A SAM resource.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySettingsAdapter setSamResource(CardResource<CalypsoSamSmartCard> samResource) {
    this.samResource = samResource;
    return this;
  }

  /**
   * (package-private) Sets the list of authorized KVC.
   *
   * @param authorizedKvcList A list of authorized KVC.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySettingsAdapter putAuthorizedKVCs(List<Byte> authorizedKvcList) {
    if (logger.isTraceEnabled()) {
      logger.trace("PoSecuritySettings authorized KVC list = {}", samResource);
    }
    this.authorizedKvcList.addAll(authorizedKvcList);
    return this;
  }

  /**
   * (package-private) Puts a map of default KIFs.
   *
   * @param defaultKIFs A map.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySettingsAdapter putDefaultKIFs(
      Map<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKIFs) {
    this.defaultKIFs.putAll(defaultKIFs);
    return this;
  }

  /**
   * (package-private) Puts a map of default KVCs.
   *
   * @param defaultKVCs A map.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySettingsAdapter putDefaultKvc(
      Map<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKVCs) {
    this.defaultKVCs.putAll(defaultKVCs);
    return this;
  }

  /**
   * (package-private) Puts a map of default key record numbers.
   *
   * @param defaultKeyRecordNumbers A map.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySettingsAdapter putDefaultKeyRecordNumbers(
      Map<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKeyRecordNumbers) {
    this.defaultKeyRecordNumbers.putAll(defaultKeyRecordNumbers);
    return this;
  }

  /**
   * (package-private) Sets the session modification mode.
   *
   * @param sessionModificationMode The session modification mode.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySettingsAdapter setSessionModificationMode(
      PoTransaction.SessionSetting.ModificationMode sessionModificationMode) {
    this.sessionModificationMode = sessionModificationMode;
    return this;
  }

  /**
   * (package-private) Sets the ratification mode.
   *
   * @param ratificationMode The ratification mode.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySettingsAdapter setRatificationMode(
      PoTransaction.SessionSetting.RatificationMode ratificationMode) {
    this.ratificationMode = ratificationMode;
    return this;
  }

  /**
   * (package-private) Sets the PIN transmission mode.
   *
   * @param pinTransmissionMode The PIN transmission mode.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySettingsAdapter setPinTransmissionMode(
      PoTransaction.PinTransmissionMode pinTransmissionMode) {
    this.pinTransmissionMode = pinTransmissionMode;
    return this;
  }

  /**
   * (package-private) Sets the default PIN ciphering key transmission mode.
   *
   * @param defaultPinCipheringKey The PIN ciphering key.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySettingsAdapter setDefaultPinCipheringKey(KeyReference defaultPinCipheringKey) {
    this.defaultPinCipheringKey = defaultPinCipheringKey;
    return this;
  }

  /**
   * (package-private) Sets the SV get log read mode.
   *
   * @param svGetLogReadMode The SV get log read mode.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySettingsAdapter setSvGetLogReadMode(
      PoTransaction.SvSettings.LogRead svGetLogReadMode) {
    this.svGetLogReadMode = svGetLogReadMode;
    return this;
  }

  /**
   * (package-private) Sets the SV negative balance mode.
   *
   * @param svNegativeBalance The SV negative balance mode.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySettingsAdapter setSvNegativeBalance(
      PoTransaction.SvSettings.NegativeBalance svNegativeBalance) {
    this.svNegativeBalance = svNegativeBalance;
    return this;
  }

  /**
   * (package-private)<br>
   *
   * @return the Sam resource
   * @since 2.0
   */
  CardResource<CalypsoSamSmartCard> getSamResource() {
    return samResource;
  }

  /**
   * (package-private)<br>
   *
   * @return the Session Modification Mode
   * @since 2.0
   */
  PoTransaction.SessionSetting.ModificationMode getSessionModificationMode() {
    return sessionModificationMode;
  }

  /**
   * (package-private)<br>
   *
   * @return the Ratification Mode
   * @since 2.0
   */
  PoTransaction.SessionSetting.RatificationMode getRatificationMode() {
    return ratificationMode;
  }

  /**
   * (package-private)<br>
   *
   * @return the PIN Transmission Mode
   * @since 2.0
   */
  public PoTransaction.PinTransmissionMode getPinTransmissionMode() {
    return pinTransmissionMode;
  }

  /**
   * (package-private)<br>
   *
   * @return the default session KIF
   * @since 2.0
   */
  Byte getSessionDefaultKif(PoTransaction.SessionSetting.AccessLevel sessionAccessLevel) {
    return defaultKIFs.get(sessionAccessLevel);
  }

  /**
   * (package-private)<br>
   *
   * @return the default session KVC
   * @since 2.0
   */
  Byte getSessionDefaultKvc(PoTransaction.SessionSetting.AccessLevel sessionAccessLevel) {
    return defaultKVCs.get(sessionAccessLevel);
  }

  /**
   * (package-private)<br>
   *
   * @return the default session key record number
   * @since 2.0
   */
  Byte getSessionDefaultKeyRecordNumber(
      PoTransaction.SessionSetting.AccessLevel sessionAccessLevel) {
    return defaultKeyRecordNumbers.get(sessionAccessLevel);
  }

  /**
   * (package-private)<br>
   * Check if the provided kvc value is authorized or not.
   *
   * <p>If no list of authorized kvc is defined (authorizedKvcList empty), all kvc are authorized.
   *
   * @param kvc to be tested.
   * @return true if the kvc is authorized
   * @since 2.0
   */
  boolean isSessionKvcAuthorized(byte kvc) {
    return authorizedKvcList.isEmpty() || authorizedKvcList.contains(kvc);
  }

  /**
   * (package-private)<br>
   *
   * @return the default key reference to be used for PIN encryption
   * @since 2.0
   */
  KeyReference getDefaultPinCipheringKey() {
    return defaultPinCipheringKey;
  }

  /**
   * (package-private)<br>
   *
   * @return how SV logs are read, indicating whether or not all SV logs are needed
   * @since 2.0
   */
  PoTransaction.SvSettings.LogRead getSvGetLogReadMode() {
    return svGetLogReadMode;
  }

  /**
   * (package-private)<br>
   *
   * @return an indication of whether negative balances are allowed or not
   * @since 2.0
   */
  PoTransaction.SvSettings.NegativeBalance getSvNegativeBalance() {
    return svNegativeBalance;
  }
}
