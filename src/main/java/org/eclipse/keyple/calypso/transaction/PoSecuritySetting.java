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
package org.eclipse.keyple.calypso.transaction;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import org.eclipse.keyple.core.util.Assert;

/**
 * This POJO contains all the needed data to manage the security operations of a Calypso
 * transaction.
 *
 * <p>Fluent setters allow to define all the required parameters, among which the resource profile
 * of the SAM card is the only mandatory one.
 *
 * @since 2.0
 */
public class PoSecuritySetting {

  private final String samCardResourceProfileName;

  // default values
  private static final PoTransactionService.SessionSetting.ModificationMode
      defaultSessionModificationMode = PoTransactionService.SessionSetting.ModificationMode.ATOMIC;
  private static final PoTransactionService.SessionSetting.RatificationMode
      defaultRatificationMode = PoTransactionService.SessionSetting.RatificationMode.CLOSE_RATIFIED;
  private static final PoTransactionService.PinTransmissionMode defaultPinTransmissionMode =
      PoTransactionService.PinTransmissionMode.ENCRYPTED;

  // fields
  PoTransactionService.SessionSetting.ModificationMode sessionModificationMode;
  PoTransactionService.SessionSetting.RatificationMode ratificationMode;
  PoTransactionService.PinTransmissionMode pinTransmissionMode;
  private final EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte> defaultKIFs;
  private final EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte> defaultKVCs;
  private final EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte>
      defaultKeyRecordNumbers;
  private List<Byte> authorizedKvcList;
  private byte defaultPinCipheringKif;
  private byte defaultPinCipheringKvc;
  private boolean isLoadAndDebitSvLogRequired;
  private boolean isSvNegativeBalanceAllowed;

  /**
   * Creates an instance of {@link PoSecuritySetting} to setup the security options for the {@link
   * PoTransactionService}.
   *
   * <p>The only mandatory parameter is the name of the SAM card resource.
   *
   * <p>The default values of the other parameters are documented in their respective getters.
   *
   * @param samCardResourceProfileName The name of the SAM card resource associated with these
   *     parameters.
   * @since 2.0
   */
  public PoSecuritySetting(String samCardResourceProfileName) {
    this.samCardResourceProfileName = samCardResourceProfileName;
    // set default values for optional parameters
    this.sessionModificationMode = defaultSessionModificationMode;
    this.ratificationMode = defaultRatificationMode;
    this.pinTransmissionMode = defaultPinTransmissionMode;
    this.defaultKIFs =
        new EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte>(
            PoTransactionService.SessionSetting.AccessLevel.class);
    this.defaultKVCs =
        new EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte>(
            PoTransactionService.SessionSetting.AccessLevel.class);
    this.defaultKeyRecordNumbers =
        new EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte>(
            PoTransactionService.SessionSetting.AccessLevel.class);
    this.authorizedKvcList = new ArrayList<Byte>();
    this.defaultPinCipheringKif = (byte) 0;
    this.defaultPinCipheringKvc = (byte) 0;
    this.isLoadAndDebitSvLogRequired = false;
    this.isSvNegativeBalanceAllowed = false;
  }

  /**
   * Set the Session Modification Mode
   *
   * @param sessionModificationMode The desired Session Modification Mode.
   * @return The object instance.
   * @throws IllegalArgumentException If the argument is null.
   * @since 2.0
   */
  public PoSecuritySetting sessionModificationMode(
      PoTransactionService.SessionSetting.ModificationMode sessionModificationMode) {
    Assert.getInstance().notNull(sessionModificationMode, "sessionModificationMode");
    this.sessionModificationMode = sessionModificationMode;
    return this;
  }

  /**
   * Set the Ratification Mode
   *
   * @param ratificationMode The desired Ratification Mode.
   * @return The object instance.
   * @throws IllegalArgumentException If the argument is null.
   * @since 2.0
   */
  public PoSecuritySetting ratificationMode(
      PoTransactionService.SessionSetting.RatificationMode ratificationMode) {
    Assert.getInstance().notNull(ratificationMode, "ratificationMode");
    this.ratificationMode = ratificationMode;
    return this;
  }

  /**
   * Set the PIN Transmission Mode
   *
   * @param pinTransmissionMode The desired PIN Transmission Mode.
   * @return The object instance.
   * @throws IllegalArgumentException If the argument is null.
   * @since 2.0
   */
  public PoSecuritySetting pinTransmissionMode(
      PoTransactionService.PinTransmissionMode pinTransmissionMode) {
    Assert.getInstance().notNull(pinTransmissionMode, "pinTransmissionMode");
    this.pinTransmissionMode = pinTransmissionMode;
    return this;
  }

  /**
   * Set the default KIF for the provide session level.
   *
   * @param sessionAccessLevel the session level.
   * @param sessionDefaultKif the desired default KIF.
   * @return The object instance.
   * @throws IllegalArgumentException If sessionAccessLevel is null.
   * @since 2.0
   */
  public PoSecuritySetting assignSessionDefaultKif(
      PoTransactionService.SessionSetting.AccessLevel sessionAccessLevel, byte sessionDefaultKif) {
    Assert.getInstance().notNull(sessionAccessLevel, "sessionAccessLevel");
    this.defaultKIFs.put(sessionAccessLevel, sessionDefaultKif);
    return this;
  }

  /**
   * Set the default KVC for the provide session level.
   *
   * @param sessionAccessLevel the session level.
   * @param sessionDefaultKvc the desired default KVC.
   * @return The object instance.
   * @throws IllegalArgumentException If sessionAccessLevel is null.
   * @since 2.0
   */
  public PoSecuritySetting assignSessionDefaultKvc(
      PoTransactionService.SessionSetting.AccessLevel sessionAccessLevel, byte sessionDefaultKvc) {
    Assert.getInstance().notNull(sessionAccessLevel, "sessionAccessLevel");
    this.defaultKVCs.put(sessionAccessLevel, sessionDefaultKvc);
    return this;
  }

  /**
   * Set the default key record number
   *
   * @param sessionAccessLevel the session level.
   * @param sessionDefaultKeyRecordNumber the desired default key record number.
   * @return The object instance.
   * @throws IllegalArgumentException If sessionAccessLevel is null.
   * @since 2.0
   */
  public PoSecuritySetting assignSessionDefaultKeyRecordNumber(
      PoTransactionService.SessionSetting.AccessLevel sessionAccessLevel,
      byte sessionDefaultKeyRecordNumber) {
    Assert.getInstance().notNull(sessionAccessLevel, "sessionAccessLevel");
    this.defaultKeyRecordNumbers.put(sessionAccessLevel, sessionDefaultKeyRecordNumber);
    return this;
  }

  /**
   * Provides a list of authorized KVC
   *
   * @param sessionAuthorizedKvcList The list of authorized KVCs.
   * @return The object instance.
   * @throws IllegalArgumentException If sessionAuthorizedKvcList is null or empty.
   * @since 2.0
   */
  public PoSecuritySetting sessionAuthorizedKvcList(List<Byte> sessionAuthorizedKvcList) {
    Assert.getInstance().notEmpty(sessionAuthorizedKvcList, "sessionAuthorizedKvcList");
    this.authorizedKvcList = sessionAuthorizedKvcList;
    return this;
  }

  /**
   * Provides the KIF/KVC pair of the PIN ciphering key
   *
   * <p>The default value for both KIF and KVC is 0.
   *
   * @param kif the KIF of the PIN ciphering key.
   * @param kvc the KVC of the PIN ciphering key.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySetting pinCipheringKey(byte kif, byte kvc) {
    this.defaultPinCipheringKif = kif;
    this.defaultPinCipheringKvc = kvc;
    return this;
  }

  /**
   * Sets the SV Get log read mode.
   *
   * <p>The default value is false.
   *
   * @param isLoadAndDebitSvLogRequired true if both Load and Debit logs are required.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySetting isLoadAndDebitSvLogRequired(boolean isLoadAndDebitSvLogRequired) {
    this.isLoadAndDebitSvLogRequired = isLoadAndDebitSvLogRequired;
    return this;
  }

  /**
   * Sets the SV negative balance.
   *
   * <p>The default value is false.
   *
   * @param isSvNegativeBalanceAllowed true if negative balance is allowed, false if not.
   * @return The object instance.
   * @since 2.0
   */
  public PoSecuritySetting isSvNegativeBalanceAllowed(boolean isSvNegativeBalanceAllowed) {
    this.isSvNegativeBalanceAllowed = isSvNegativeBalanceAllowed;
    return this;
  }

  /**
   * Gets the SAM card resource profile name.
   *
   * @return A not empty string.
   * @since 2.0
   */
  public String getCardResourceProfileName() {
    return samCardResourceProfileName;
  }

  /**
   * Gets the Session Modification Mode.
   *
   * <p>The default value is {@link PoTransactionService.SessionSetting.ModificationMode#ATOMIC}.
   *
   * @return A not null reference.
   * @since 2.0
   */
  public PoTransactionService.SessionSetting.ModificationMode getSessionModificationMode() {
    return sessionModificationMode;
  }

  /**
   * Gets the Ratification Mode.
   *
   * <p>The default value is {@link
   * PoTransactionService.SessionSetting.RatificationMode#CLOSE_RATIFIED}.
   *
   * @return A not null reference.
   * @since 2.0
   */
  public PoTransactionService.SessionSetting.RatificationMode getRatificationMode() {
    return ratificationMode;
  }

  /**
   * Gets the PIN Transmission Mode.
   *
   * <p>The default value is {@link PoTransactionService.PinTransmissionMode#ENCRYPTED}.
   *
   * @return A not null reference.
   * @since 2.0
   */
  public PoTransactionService.PinTransmissionMode getPinTransmissionMode() {
    return pinTransmissionMode;
  }

  /**
   * Gets the default session KIF for the provided session level.
   *
   * <p>TODO check what default values should be used here.
   *
   * @param sessionAccessLevel The session level.
   * @return null if no value has been set.
   * @since 2.0
   */
  public Byte getSessionDefaultKif(
      PoTransactionService.SessionSetting.AccessLevel sessionAccessLevel) {
    return defaultKIFs.get(sessionAccessLevel);
  }

  /**
   * Gets the default session KVC for the provided session level.
   *
   * <p>TODO check what default values should be used here.
   *
   * @param sessionAccessLevel The session level.
   * @return null if no value has been set.
   * @since 2.0
   */
  public Byte getSessionDefaultKvc(
      PoTransactionService.SessionSetting.AccessLevel sessionAccessLevel) {
    return defaultKVCs.get(sessionAccessLevel);
  }

  /**
   * Gets the default session key record number for the provided session level.
   *
   * <p>TODO check what default values should be used here.
   *
   * @param sessionAccessLevel The session level.
   * @return null if no value has been set.
   * @since 2.0
   */
  public Byte getSessionDefaultKeyRecordNumber(
      PoTransactionService.SessionSetting.AccessLevel sessionAccessLevel) {
    return defaultKeyRecordNumbers.get(sessionAccessLevel);
  }

  /**
   * Check if the provided KVC value is authorized or not.
   *
   * <p>If no list of authorized kvc is defined (authorizedKvcList empty), the method returns true
   * regardless of the value provided.
   *
   * @param kvc The KVC value to be check.
   * @return true if the kvc is authorized or if no authorization list has been defined.
   * @since 2.0
   */
  public boolean isSessionKvcAuthorized(byte kvc) {
    return authorizedKvcList.isEmpty() || authorizedKvcList.contains(kvc);
  }

  /**
   * Gets the default KIF to be used for PIN encryption.
   *
   * <p>The default value is 0.
   *
   * @return A byte.
   * @since 2.0
   */
  public byte getDefaultPinCipheringKif() {
    return defaultPinCipheringKif;
  }

  /**
   * Gets the default KVC to be used for PIN encryption.
   *
   * <p>The default value is 0.
   *
   * @return A byte.
   * @since 2.0
   */
  public byte getDefaultPinCipheringKvc() {
    return defaultPinCipheringKvc;
  }

  /**
   * Indicates whether both the debit and load logs must be retrieved during SV operations.
   *
   * <p>The default value is false.
   *
   * @return true if both logs are required, false if not.
   * @since 2.0
   */
  public boolean isLoadAndDebitSvLogRequired() {
    return isLoadAndDebitSvLogRequired;
  }

  /**
   * Indicates whether negative balances are allowed in SV transactions.
   *
   * <p>The default value is false.
   *
   * @return true if negative balances are allowed, false if not.
   * @since 2.0
   */
  public boolean isSvNegativeBalanceAllowed() {
    return isSvNegativeBalanceAllowed;
  }
}
