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

import java.util.EnumMap;
import java.util.List;
import org.eclipse.keyple.calypso.smartcard.sam.CalypsoSamSmartCard;
import org.eclipse.keyple.calypso.transaction.PoSecuritySettingsInterface;
import org.eclipse.keyple.calypso.transaction.PoTransaction;
import org.eclipse.keyple.core.service.selection.CardResource;

public class PoSecuritySettingsAdapter implements PoSecuritySettingsInterface {
  private CardResource<CalypsoSamSmartCard> samResource;
  /** List of authorized KVCs */
  private List<Byte> authorizedKvcList;

  /** EnumMap associating session levels and corresponding KIFs */
  private EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKif;

  private EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKvc;
  private EnumMap<PoTransaction.SessionSetting.AccessLevel, Byte> defaultKeyRecordNumber;

  private PoTransaction.SessionSetting.ModificationMode sessionModificationMode;
  private PoTransaction.SessionSetting.RatificationMode ratificationMode;
  private PoTransaction.PinTransmissionMode pinTransmissionMode;
  private KeyReference defaultPinCipheringKey;
  private PoTransaction.SvSettings.LogRead svGetLogReadMode;
  private PoTransaction.SvSettings.NegativeBalance svNegativeBalance;

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
