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

import org.calypsonet.terminal.calypso.WriteAccessLevel;

class SymmetricKeySecuritySettingAdapter implements SymmetricKeySecuritySetting {

  @Override
  public SymmetricKeySecuritySetting enableMultipleSession() {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting setCryptoService(SymmetricCryptoService cryptoService) {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting enableEarlyMutualAuthentication() {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting enableRatificationMechanism() {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting enablePinPlainTransmission() {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting enableSvLoadAndDebitLog() {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting authorizeSvNegativeBalance() {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting forceRegularMode() {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting assignKif(
      WriteAccessLevel writeAccessLevel, byte kvc, byte kif) {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting assignDefaultKif(WriteAccessLevel writeAccessLevel, byte kif) {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting assignDefaultKvc(WriteAccessLevel writeAccessLevel, byte kvc) {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting addAuthorizedSessionKey(byte kif, byte kvc) {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting addAuthorizedSvKey(byte kif, byte kvc) {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting setPinVerificationCipheringKey(byte kif, byte kvc) {
    return null;
  }

  @Override
  public SymmetricKeySecuritySetting setPinModificationCipheringKey(byte kif, byte kvc) {
    return null;
  }
}
