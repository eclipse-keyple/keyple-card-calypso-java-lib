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
import org.eclipse.keyple.calypso.transaction.PoSecuritySetting;
import org.eclipse.keyple.calypso.transaction.PoTransactionService;
import org.eclipse.keyple.core.util.Assert;

/**
 * Builds instances of {@link PoSecuritySetting} from values configured by the setters.
 *
 * <p>The object provides default values when instantiated, a fluent builder to adjust the settings
 * to the application needs.
 *
 * @since 2.0
 */
public class PoSecuritySettingBuilder {

  public static final PoTransactionService.SessionSetting.ModificationMode
      defaultSessionModificationMode = PoTransactionService.SessionSetting.ModificationMode.ATOMIC;
  public static final PoTransactionService.SessionSetting.RatificationMode defaultRatificationMode =
      PoTransactionService.SessionSetting.RatificationMode.CLOSE_RATIFIED;
  public static final PoTransactionService.PinTransmissionMode defaultPinTransmissionMode =
      PoTransactionService.PinTransmissionMode.ENCRYPTED;
  private static final KeyReference nullPinCipheringKey = new KeyReference((byte) 0, (byte) 0);
  private static final PoTransactionService.SvSettings.LogRead defaultSvGetLogReadMode =
      PoTransactionService.SvSettings.LogRead.SINGLE;
  private static final PoTransactionService.SvSettings.NegativeBalance defaultSvNegativeBalance =
      PoTransactionService.SvSettings.NegativeBalance.FORBIDDEN;

  /** Private constructor */
  private PoSecuritySettingBuilder() {}

  /**
   * Creates builder to build a {@link PoSecuritySettingBuilder}.
   *
   * <p>A SAM resource has to be provided and is the only mandatory setting.
   *
   * @param samProfileName The SAM profile name.
   * @return created builder
   * @since 2.0
   */
  public static Builder builder(String samProfileName) {
    return new Builder(samProfileName);
  }

  /**
   * Builder class for {@link PoSecuritySettingBuilder}
   *
   * @since 2.0
   */
  public static final class Builder {
    private final String samProfileName;
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
    KeyReference defaultPinCipheringKey = nullPinCipheringKey;
    PoTransactionService.SvSettings.LogRead svGetLogReadMode = defaultSvGetLogReadMode;
    PoTransactionService.SvSettings.NegativeBalance svNegativeBalanceMode =
        defaultSvNegativeBalance;

    /**
     * Constructor The SAM resource we'll be working with is needed in any cases.
     *
     * @param samProfileName The SAM profile name.
     * @throws IllegalArgumentException If the argument is null.
     * @since 2.0
     */
    public Builder(String samProfileName) {
      Assert.getInstance().notEmpty(samProfileName, "samResource");
      this.samProfileName = samProfileName;
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
    public Builder sessionModificationMode(
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
    public Builder ratificationMode(
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
    public Builder pinTransmissionMode(
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
    public Builder assignSessionDefaultKif(
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
    public Builder assignSessionDefaultKvc(
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
    public Builder assignSessionDefaultKeyRecordNumber(
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
    public Builder sessionAuthorizedKvcList(List<Byte> sessionAuthorizedKvcList) {
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
    public Builder pinCipheringKey(byte kif, byte kvc) {
      this.defaultPinCipheringKey = new KeyReference(kif, kvc);
      return this;
    }

    /**
     * Sets the SV Get log read mode to indicate whether only one or both log files are to be read
     *
     * @param svGetLogReadMode the {@link PoTransactionService.SvSettings.LogRead} mode.
     * @return the builder instance
     * @throws IllegalArgumentException If sessionAccessLevel is null.
     * @since 2.0
     */
    public Builder svGetLogReadMode(PoTransactionService.SvSettings.LogRead svGetLogReadMode) {
      Assert.getInstance().notNull(svGetLogReadMode, "svGetLogReadMode");
      this.svGetLogReadMode = svGetLogReadMode;
      return this;
    }

    /**
     * Sets the SV negative balance mode to indicate whether negative balances are allowed or not
     *
     * @param svNegativeBalanceMode the {@link PoTransactionService.SvSettings.NegativeBalance}
     *     mode.
     * @return the builder instance
     * @throws IllegalArgumentException If sessionAccessLevel is null.
     * @since 2.0
     */
    public Builder svNegativeBalanceMode(
        PoTransactionService.SvSettings.NegativeBalance svNegativeBalanceMode) {
      Assert.getInstance().notNull(svNegativeBalanceMode, "svNegativeBalanceMode");
      this.svNegativeBalanceMode = svNegativeBalanceMode;
      return this;
    }

    /**
     * Build a new instance of {@code PoSecuritySetting}.
     *
     * @return A not null reference.
     * @since 2.0
     */
    public PoSecuritySetting build() {
      return new PoSecuritySettingAdapter()
          .setSamResource(samProfileName)
          .putAuthorizedKVCs(authorizedKvcList)
          .putDefaultKIFs(defaultKif)
          .putDefaultKvc(defaultKvc)
          .putDefaultKeyRecordNumbers(defaultKeyRecordNumber)
          .setSessionModificationMode(sessionModificationMode)
          .setRatificationMode(ratificationMode)
          .setPinTransmissionMode(pinTransmissionMode)
          .setDefaultPinCipheringKey(defaultPinCipheringKey)
          .setSvGetLogReadMode(svGetLogReadMode)
          .setSvNegativeBalance(svNegativeBalanceMode);
    }
  }
}
