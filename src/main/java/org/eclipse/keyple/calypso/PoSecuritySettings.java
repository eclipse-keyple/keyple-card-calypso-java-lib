/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://www.calypsonet-asso.org/
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

import java.util.EnumMap;
import java.util.List;
import org.eclipse.keyple.calypso.smartcard.sam.CalypsoSamSmartCard;
import org.eclipse.keyple.calypso.transaction.PoTransaction;
import org.eclipse.keyple.core.service.selection.CardResource;

/**
 * Manages the security settings involved in Calypso secure sessions.
 *
 * <p>The object provides default values when instantiated, a fluent builder to adjust the settings
 * to the application needs.
 *
 * @since 2.0
 */
public class PoSecuritySettings {
  private final CardResource<CalypsoSamSmartCard> samResource;
  /** List of authorized KVCs */
  private final List<Byte> authorizedKvcList;

  /** EnumMap associating session levels and corresponding KIFs */
  private final EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKif;

  private final EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKvc;
  private final EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKeyRecordNumber;

  private final PoTransaction.SessionSetting.ModificationMode sessionModificationMode;
  private final PoTransaction.SessionSetting.RatificationMode ratificationMode;
  private final PoTransaction.PinTransmissionMode pinTransmissionMode;
  private final KeyReference defaultPinCipheringKey;
  private final PoTransaction.SvSettings.LogRead svGetLogReadMode;
  private final PoTransaction.SvSettings.NegativeBalance svNegativeBalance;

  public static final PoTransaction.SessionSetting.ModificationMode defaultSessionModificationMode =
      PoTransaction.SessionSetting.ModificationMode.ATOMIC;
  public static final PoTransaction.SessionSetting.RatificationMode defaultRatificationMode =
      PoTransaction.SessionSetting.RatificationMode.CLOSE_RATIFIED;
  public static final PoTransaction.PinTransmissionMode defaultPinTransmissionMode =
      PoTransaction.PinTransmissionMode.ENCRYPTED;
  private static final KeyReference nullPinCipheringKey = new KeyReference((byte) 0, (byte) 0);
  private static final PoTransaction.SvSettings.LogRead defaultSvGetLogReadMode =
      PoTransaction.SvSettings.LogRead.SINGLE;
  private static final PoTransaction.SvSettings.NegativeBalance defaultSvNegativeBalance =
      PoTransaction.SvSettings.NegativeBalance.FORBIDDEN;

  /** Private constructor */
  private PoSecuritySettings(PoSecuritySettingsBuilder builder) {
    this.samResource = builder.samResource;
    this.authorizedKvcList = builder.authorizedKvcList;
    this.defaultKif = builder.defaultKif;
    this.defaultKvc = builder.defaultKvc;
    this.defaultKeyRecordNumber = builder.defaultKeyRecordNumber;
    this.sessionModificationMode = builder.sessionModificationMode;
    this.ratificationMode = builder.ratificationMode;
    this.pinTransmissionMode = builder.pinTransmissionMode;
    this.defaultPinCipheringKey = builder.defaultPinCipheringKey;
    this.svGetLogReadMode = builder.svGetLogReadMode;
    this.svNegativeBalance = builder.svNegativeBalance;
  }

  /**
   * Builder class for {@link PoSecuritySettings}
   *
   * @since 2.0
   */
  public static final class PoSecuritySettingsBuilder {
    private final CardResource<CalypsoSamSmartCard> samResource;
    /** List of authorized KVCs */
    private List<Byte> authorizedKvcList;

    /** EnumMap associating session levels and corresponding KIFs */
    private final EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKif =
        new EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte>(
            PoTransaction.SessionSetting.AccessLevel.class);

    private final EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKvc =
        new EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte>(
            PoTransaction.SessionSetting.AccessLevel.class);
    private final EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKeyRecordNumber =
        new EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte>(
            PoTransaction.SessionSetting.AccessLevel.class);

    PoTransaction.SessionSetting.ModificationMode sessionModificationMode =
        defaultSessionModificationMode;
    PoTransaction.SessionSetting.RatificationMode ratificationMode = defaultRatificationMode;
    PoTransaction.PinTransmissionMode pinTransmissionMode = defaultPinTransmissionMode;
    KeyReference defaultPinCipheringKey = nullPinCipheringKey;
    PoTransaction.SvSettings.LogRead svGetLogReadMode = defaultSvGetLogReadMode;
    PoTransaction.SvSettings.NegativeBalance svNegativeBalance = defaultSvNegativeBalance;

    /**
     * Constructor
     *
     * @param samResource the SAM resource we'll be working with<br>
     *     Needed in any cases.
     * @since 2.0
     */
    public PoSecuritySettingsBuilder(CardResource<CalypsoSamSmartCard> samResource) {
      if (samResource == null) {
        throw new IllegalStateException("SAM resource cannot be null.");
      }
      this.samResource = samResource;
    }

    /**
     * Set the Session Modification Mode<br>
     * The default value is ATOMIC
     *
     * @param sessionModificationMode the desired Session Modification Mode.
     * @return the builder instance
     * @since 2.0
     */
    public PoSecuritySettingsBuilder sessionModificationMode(
        PoTransaction.SessionSetting.ModificationMode sessionModificationMode) {
      this.sessionModificationMode = sessionModificationMode;
      return this;
    }

    /**
     * Set the Ratification Mode<br>
     * The default value is CLOSE_RATIFIED
     *
     * @param ratificationMode the desired Ratification Mode.
     * @return the builder instance
     * @since 2.0
     */
    public PoSecuritySettingsBuilder ratificationMode(
        PoTransaction.SessionSetting.RatificationMode ratificationMode) {
      this.ratificationMode = ratificationMode;
      return this;
    }

    /**
     * Set the PIN Transmission Mode<br>
     * The default value is ENCRYPTED
     *
     * @param pinTransmissionMode the desired PIN Transmission Mode.
     * @return the builder instance
     * @since 2.0
     */
    public PoSecuritySettingsBuilder pinTransmissionMode(
        PoTransaction.PinTransmissionMode pinTransmissionMode) {
      this.pinTransmissionMode = pinTransmissionMode;
      return this;
    }

    /**
     * Set the default KIF<br>
     *
     * @param sessionAccessLevel the session level.
     * @param kif the desired default KIF.
     * @return the builder instance
     * @since 2.0
     */
    public PoSecuritySettingsBuilder sessionDefaultKif(
        PoTransaction.SessionSetting.AccessLevel sessionAccessLevel, byte kif) {
      defaultKif.put(sessionAccessLevel, kif);
      return this;
    }

    /**
     * Set the default KVC<br>
     *
     * @param sessionAccessLevel the session level.
     * @param kvc the desired default KVC.
     * @return the builder instance
     * @since 2.0
     */
    public PoSecuritySettingsBuilder sessionDefaultKvc(
        PoTransaction.SessionSetting.AccessLevel sessionAccessLevel, byte kvc) {
      defaultKvc.put(sessionAccessLevel, kvc);
      return this;
    }

    /**
     * Set the default key record number<br>
     *
     * @param sessionAccessLevel the session level.
     * @param keyRecordNumber the desired default key record number.
     * @return the builder instance
     * @since 2.0
     */
    public PoSecuritySettingsBuilder sessionDefaultKeyRecordNumber(
        PoTransaction.SessionSetting.AccessLevel sessionAccessLevel, byte keyRecordNumber) {
      defaultKeyRecordNumber.put(sessionAccessLevel, keyRecordNumber);
      return this;
    }

    /**
     * Provides a list of authorized KVC
     *
     * <p>If this method is not called, the list will remain empty and all KVCs will be accepted.
     *
     * @param authorizedKvcList the list of authorized KVCs.
     * @return the builder instance
     * @since 2.0
     */
    public PoSecuritySettingsBuilder sessionAuthorizedKvcList(List<Byte> authorizedKvcList) {
      this.authorizedKvcList = authorizedKvcList;
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
    public PoSecuritySettingsBuilder pinCipheringKey(byte kif, byte kvc) {
      this.defaultPinCipheringKey = new KeyReference(kif, kvc);
      return this;
    }

    /**
     * Sets the SV Get log read mode to indicate whether only one or both log files are to be read
     *
     * @param svGetLogReadMode the {@link PoTransaction.SvSettings.LogRead} mode.
     * @return the builder instance
     * @since 2.0
     */
    public PoSecuritySettingsBuilder svGetLogReadMode(
        PoTransaction.SvSettings.LogRead svGetLogReadMode) {
      this.svGetLogReadMode = svGetLogReadMode;
      return this;
    }

    /**
     * Sets the SV negative balance mode to indicate whether negative balances are allowed or not
     *
     * @param svNegativeBalance the {@link PoTransaction.SvSettings.NegativeBalance} mode.
     * @return the builder instance
     * @since 2.0
     */
    public PoSecuritySettingsBuilder svNegativeBalance(
        PoTransaction.SvSettings.NegativeBalance svNegativeBalance) {
      this.svNegativeBalance = svNegativeBalance;
      return this;
    }

    /**
     * Build a new {@code PoSecuritySettings}.
     *
     * @return a new instance
     * @since 2.0
     */
    public PoSecuritySettings build() {
      return new PoSecuritySettings(this);
    }
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
    return defaultKif.get(sessionAccessLevel);
  }

  /**
   * (package-private)<br>
   *
   * @return the default session KVC
   * @since 2.0
   */
  Byte getSessionDefaultKvc(PoTransaction.SessionSetting.AccessLevel sessionAccessLevel) {
    return defaultKvc.get(sessionAccessLevel);
  }

  /**
   * (package-private)<br>
   *
   * @return the default session key record number
   * @since 2.0
   */
  Byte getSessionDefaultKeyRecordNumber(
      PoTransaction.SessionSetting.AccessLevel sessionAccessLevel) {
    return defaultKeyRecordNumber.get(sessionAccessLevel);
  }

  /**
   * (package-private)<br>
   * Check if the provided kvc value is authorized or not.
   *
   * <p>If no list of authorized kvc is defined (authorizedKvcList null), all kvc are authorized.
   *
   * @param kvc to be tested.
   * @return true if the kvc is authorized
   * @since 2.0
   */
  boolean isSessionKvcAuthorized(byte kvc) {
    return authorizedKvcList == null || authorizedKvcList.contains(kvc);
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
