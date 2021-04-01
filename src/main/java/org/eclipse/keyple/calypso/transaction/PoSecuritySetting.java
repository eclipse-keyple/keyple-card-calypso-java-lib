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
 * <p>A fluent builder allows to define all the required parameters, among which the resource
 * profile of the SAM card is the only mandatory one.
 *
 * @since 2.0
 */
public class PoSecuritySetting {

  private final String samCardResourceProfileName;
  private final List<Byte> authorizedKvcList;
  private final EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte> defaultKIFs;
  private final EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte> defaultKVCs;
  private final EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte>
      defaultKeyRecordNumbers;
  private final PoTransactionService.SessionSetting.ModificationMode sessionModificationMode;
  private final PoTransactionService.SessionSetting.RatificationMode ratificationMode;
  private final PoTransactionService.PinTransmissionMode pinTransmissionMode;
  private final boolean isLoadAndDebitSvLogRequired;
  private final boolean isSvNegativeBalanceAllowed;
  private final byte defaultPinCipheringKif;
  private final byte defaultPinCipheringKvc;

  /**
   * CalypsoSamCardSelectorBuilder of {@link PoSecuritySetting}.
   *
   * @since 2.0
   */
  public static final class PoSecuritySettingBuilder {
    private static final PoTransactionService.SessionSetting.ModificationMode
        defaultSessionModificationMode =
            PoTransactionService.SessionSetting.ModificationMode.ATOMIC;
    private static final PoTransactionService.SessionSetting.RatificationMode
        defaultRatificationMode =
            PoTransactionService.SessionSetting.RatificationMode.CLOSE_RATIFIED;
    private static final PoTransactionService.PinTransmissionMode defaultPinTransmissionMode =
        PoTransactionService.PinTransmissionMode.ENCRYPTED;
    private boolean isLoadAndDebitSvLogRequired = false;
    private boolean isSvNegativeBalanceAllowed = false;
    private final String samCardResourceProfileName;
    /** List of authorized KVCs */
    private List<Byte> authorizedKvcList;

    /** EnumMap associating session levels and corresponding KIFs */
    private final EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte> defaultKif =
        new EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte>(
            PoTransactionService.SessionSetting.AccessLevel.class);

    private final EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte> defaultKvc =
        new EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte>(
            PoTransactionService.SessionSetting.AccessLevel.class);
    private final EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte>
        defaultKeyRecordNumber =
            new EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte>(
                PoTransactionService.SessionSetting.AccessLevel.class);

    PoTransactionService.SessionSetting.ModificationMode sessionModificationMode =
        defaultSessionModificationMode;
    PoTransactionService.SessionSetting.RatificationMode ratificationMode = defaultRatificationMode;
    PoTransactionService.PinTransmissionMode pinTransmissionMode = defaultPinTransmissionMode;
    private byte defaultPinCipheringKif = (byte) 0;
    private byte defaultPinCipheringKvc = (byte) 0;

    /**
     * (private)<br>
     * Creates an instance.
     *
     * @param samCardResourceProfileName The SAM profile name.
     * @throws IllegalArgumentException If the name is null or empty.
     * @since 2.0
     */
    public PoSecuritySettingBuilder(String samCardResourceProfileName) {
      Assert.getInstance().notEmpty(samCardResourceProfileName, "samCardResourceProfileName");
      this.samCardResourceProfileName = samCardResourceProfileName;
    }

    /**
     * Set the Session Modification Mode
     *
     * <p>The default value is {@link PoTransactionService.SessionSetting.ModificationMode#ATOMIC}.
     *
     * @param sessionModificationMode The desired Session Modification Mode.
     * @return the builder instance
     * @throws IllegalArgumentException If the argument is null.
     * @since 2.0
     */
    public PoSecuritySettingBuilder sessionModificationMode(
        PoTransactionService.SessionSetting.ModificationMode sessionModificationMode) {
      Assert.getInstance().notNull(sessionModificationMode, "sessionModificationMode");
      this.sessionModificationMode = sessionModificationMode;
      return this;
    }

    /**
     * Set the Ratification Mode
     *
     * <p>The default value is {@link
     * PoTransactionService.SessionSetting.RatificationMode#CLOSE_RATIFIED}.
     *
     * @param ratificationMode The desired Ratification Mode.
     * @return the builder instance
     * @throws IllegalArgumentException If the argument is null.
     * @since 2.0
     */
    public PoSecuritySettingBuilder ratificationMode(
        PoTransactionService.SessionSetting.RatificationMode ratificationMode) {
      Assert.getInstance().notNull(ratificationMode, "ratificationMode");
      this.ratificationMode = ratificationMode;
      return this;
    }

    /**
     * Set the PIN Transmission Mode
     *
     * <p>The default value is {@link PoTransactionService.PinTransmissionMode#ENCRYPTED}.
     *
     * @param pinTransmissionMode The desired PIN Transmission Mode.
     * @return the builder instance
     * @throws IllegalArgumentException If the argument is null.
     * @since 2.0
     */
    public PoSecuritySettingBuilder pinTransmissionMode(
        PoTransactionService.PinTransmissionMode pinTransmissionMode) {
      Assert.getInstance().notNull(pinTransmissionMode, "pinTransmissionMode");
      this.pinTransmissionMode = pinTransmissionMode;
      return this;
    }

    /**
     * Set the default KIF for the provide session level.
     *
     * <p>TODO check what default values should be used here.
     *
     * @param sessionAccessLevel the session level.
     * @param sessionDefaultKif the desired default KIF.
     * @return the builder instance
     * @throws IllegalArgumentException If sessionAccessLevel is null.
     * @since 2.0
     */
    public PoSecuritySettingBuilder assignSessionDefaultKif(
        PoTransactionService.SessionSetting.AccessLevel sessionAccessLevel,
        byte sessionDefaultKif) {
      Assert.getInstance().notNull(sessionAccessLevel, "sessionAccessLevel");
      defaultKif.put(sessionAccessLevel, sessionDefaultKif);
      return this;
    }

    /**
     * Set the default KVC for the provide session level.
     *
     * <p>TODO check what default values should be used here.
     *
     * @param sessionAccessLevel the session level.
     * @param sessionDefaultKvc the desired default KVC.
     * @return the builder instance
     * @throws IllegalArgumentException If sessionAccessLevel is null.
     * @since 2.0
     */
    public PoSecuritySettingBuilder assignSessionDefaultKvc(
        PoTransactionService.SessionSetting.AccessLevel sessionAccessLevel,
        byte sessionDefaultKvc) {
      Assert.getInstance().notNull(sessionAccessLevel, "sessionAccessLevel");
      this.defaultKvc.put(sessionAccessLevel, sessionDefaultKvc);
      return this;
    }

    /**
     * Set the default key record number
     *
     * <p>TODO check what default values should be used here.
     *
     * @param sessionAccessLevel the session level.
     * @param sessionDefaultKeyRecordNumber the desired default key record number.
     * @return the builder instance
     * @throws IllegalArgumentException If sessionAccessLevel is null.
     * @since 2.0
     */
    public PoSecuritySettingBuilder assignSessionDefaultKeyRecordNumber(
        PoTransactionService.SessionSetting.AccessLevel sessionAccessLevel,
        byte sessionDefaultKeyRecordNumber) {
      Assert.getInstance().notNull(sessionAccessLevel, "sessionAccessLevel");
      defaultKeyRecordNumber.put(sessionAccessLevel, sessionDefaultKeyRecordNumber);
      return this;
    }

    /**
     * Provides a list of authorized KVC
     *
     * <p>If this method is not called, the list will remain empty and all KVCs will be accepted.
     *
     * @param sessionAuthorizedKvcList the list of authorized KVCs.
     * @return the builder instance
     * @throws IllegalArgumentException If sessionAuthorizedKvcList is null or empty.
     * @since 2.0
     */
    public PoSecuritySettingBuilder sessionAuthorizedKvcList(List<Byte> sessionAuthorizedKvcList) {
      Assert.getInstance().notEmpty(sessionAuthorizedKvcList, "sessionAuthorizedKvcList");
      this.authorizedKvcList = sessionAuthorizedKvcList;
      return this;
    }

    /**
     * Provides the KIF/KVC pair of the PIN ciphering key
     *
     * @param kif the KIF of the PIN ciphering key.
     * @param kvc the KVC of the PIN ciphering key.
     * @return the builder instance
     * @since 2.0
     */
    public PoSecuritySettingBuilder pinCipheringKey(byte kif, byte kvc) {
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
     * @return the builder instance
     * @since 2.0
     */
    public PoSecuritySettingBuilder isLoadAndDebitSvLogRequired(
        boolean isLoadAndDebitSvLogRequired) {
      this.isLoadAndDebitSvLogRequired = isLoadAndDebitSvLogRequired;
      return this;
    }

    /**
     * Sets the SV negative balance.
     *
     * <p>The default value is false.
     *
     * @param isSvNegativeBalanceAllowed true if negative balance is allowed, false if not.
     * @return the builder instance
     * @since 2.0
     */
    public PoSecuritySettingBuilder isSvNegativeBalanceAllowed(boolean isSvNegativeBalanceAllowed) {
      this.isSvNegativeBalanceAllowed = isSvNegativeBalanceAllowed;
      return this;
    }

    /**
     * Build a new instance of {@code PoSecuritySetting}.
     *
     * @return A not null reference.
     * @since 2.0
     */
    public PoSecuritySetting build() {
      return new PoSecuritySetting(this);
    }
  }

  /**
   * Gets a new builder of {@link PoSecuritySetting} using the provided card resource profile name.
   *
   * @param samCardResourceProfileName The SAM card resource profile name.
   * @return A new builder instance.
   * @since 2.0
   */
  public static PoSecuritySettingBuilder builder(String samCardResourceProfileName) {
    Assert.getInstance().notEmpty(samCardResourceProfileName, "samCardResourceProfileName");
    return new PoSecuritySettingBuilder(samCardResourceProfileName);
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
   * @return A not null reference.
   * @since 2.0
   */
  public PoTransactionService.SessionSetting.ModificationMode getSessionModificationMode() {
    return sessionModificationMode;
  }

  /**
   * Gets the Ratification Mode.
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
   * @return A not null reference.
   * @since 2.0
   */
  public PoTransactionService.PinTransmissionMode getPinTransmissionMode() {
    return pinTransmissionMode;
  }

  /**
   * Gets the default session KIF for the provided session level.
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

  /**
   * (private)<br>
   * Creates an instance of {@link PoSecuritySetting}.
   */
  private PoSecuritySetting(PoSecuritySettingBuilder builder) {
    // TODO check if we need thread safe collections here
    authorizedKvcList = new ArrayList<Byte>();
    defaultKIFs =
        new EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte>(
            PoTransactionService.SessionSetting.AccessLevel.class);
    defaultKVCs =
        new EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte>(
            PoTransactionService.SessionSetting.AccessLevel.class);
    defaultKeyRecordNumbers =
        new EnumMap<PoTransactionService.SessionSetting.AccessLevel, Byte>(
            PoTransactionService.SessionSetting.AccessLevel.class);
    this.samCardResourceProfileName = builder.samCardResourceProfileName;
    this.authorizedKvcList.addAll(builder.authorizedKvcList);
    this.defaultKIFs.putAll(builder.defaultKif);
    this.defaultKVCs.putAll(builder.defaultKvc);
    this.defaultKeyRecordNumbers.putAll(builder.defaultKeyRecordNumber);
    this.sessionModificationMode = builder.sessionModificationMode;
    this.ratificationMode = builder.ratificationMode;
    this.pinTransmissionMode = builder.pinTransmissionMode;
    this.defaultPinCipheringKif = builder.defaultPinCipheringKif;
    this.defaultPinCipheringKvc = builder.defaultPinCipheringKvc;
    this.isLoadAndDebitSvLogRequired = builder.isLoadAndDebitSvLogRequired;
    this.isSvNegativeBalanceAllowed = builder.isSvNegativeBalanceAllowed;
  }
}
