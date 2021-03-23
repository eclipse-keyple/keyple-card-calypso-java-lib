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
  private PoSecuritySettings(Builder builder) {
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
  public static final class Builder {
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
    public Builder(CardResource<CalypsoSamSmartCard> samResource) {
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
    public Builder sessionModificationMode(
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
    public Builder ratificationMode(
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
    public Builder pinTransmissionMode(PoTransaction.PinTransmissionMode pinTransmissionMode) {
      this.pinTransmissionMode = pinTransmissionMode;
      return this;
    }

    /**
     * Set the default KIF for the provide session level.<br>
     *
     * @param sessionAccessLevel the session level.
     * @param sessionDefaultKif the desired default KIF.
     * @return the builder instance
     * @since 2.0
     */
    public Builder assignSessionDefaultKif(
        PoTransaction.SessionSetting.AccessLevel sessionAccessLevel, byte sessionDefaultKif) {
      defaultKif.put(sessionAccessLevel, sessionDefaultKif);
      return this;
    }

    /**
     * Set the default KVC for the provide session level.<br>
     *
     * @param sessionAccessLevel the session level.
     * @param sessionDefaultKvc the desired default KVC.
     * @return the builder instance
     * @since 2.0
     */
    public Builder assignSessionDefaultKvc(
        PoTransaction.SessionSetting.AccessLevel sessionAccessLevel, byte sessionDefaultKvc) {
      this.defaultKvc.put(sessionAccessLevel, sessionDefaultKvc);
      return this;
    }

    /**
     * Set the default key record number<br>
     *
     * @param sessionAccessLevel the session level.
     * @param sessionDefaultKeyRecordNumber the desired default key record number.
     * @return the builder instance
     * @since 2.0
     */
    public Builder assignSessionDefaultKeyRecordNumber(
        PoTransaction.SessionSetting.AccessLevel sessionAccessLevel,
        byte sessionDefaultKeyRecordNumber) {
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
     * @since 2.0
     */
    public Builder sessionAuthorizedKvcList(List<Byte> sessionAuthorizedKvcList) {
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
    public Builder pinCipheringKey(byte kif, byte kvc) {
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
    public Builder svGetLogReadMode(PoTransaction.SvSettings.LogRead svGetLogReadMode) {
      this.svGetLogReadMode = svGetLogReadMode;
      return this;
    }

    /**
     * Sets the SV negative balance mode to indicate whether negative balances are allowed or not
     *
     * @param svNegativeBalanceMode the {@link PoTransaction.SvSettings.NegativeBalance} mode.
     * @return the builder instance
     * @since 2.0
     */
    public Builder svNegativeBalanceMode(
        PoTransaction.SvSettings.NegativeBalance svNegativeBalanceMode) {
      this.svNegativeBalance = svNegativeBalanceMode;
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
}
