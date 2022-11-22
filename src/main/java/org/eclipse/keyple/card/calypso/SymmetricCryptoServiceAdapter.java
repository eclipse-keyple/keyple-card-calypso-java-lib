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

class SymmetricCryptoServiceAdapter implements SymmetricCryptoService, SymmetricCryptoServiceSpi {

  @Override
  public void setKeyDiversifier(byte[] keyDiversifier) {}

  @Override
  public byte[] initTerminalSecureSessionContext() {
    return new byte[0];
  }

  @Override
  public void initTerminalSessionMac(byte[] openSecureSessionDataOut, byte kif, byte kvc) {}

  @Override
  public byte[] updateTerminalSessionMac(byte[] cardApdu) {
    return new byte[0];
  }

  @Override
  public byte[] finalizeTerminalSessionMac() {
    return new byte[0];
  }

  @Override
  public byte[] generateTerminalSessionMac() {
    return new byte[0];
  }

  @Override
  public void activateEncryption() {}

  @Override
  public void deactivateEncryption() {}

  @Override
  public boolean verifyCardSessionMac(byte[] cardSessionMac) {
    return false;
  }

  @Override
  public void generateSvCommandSecurityData(SvCommandSecurityData svCommandSecurityData) {}

  @Override
  public boolean verifyCardSvMac(byte[] cardSvMac) {
    return false;
  }

  @Override
  public byte[] cipherPinForPresentation(byte[] cardChallenge, byte[] pin, byte kif, byte kvc) {
    return new byte[0];
  }

  @Override
  public byte[] cipherPinForModification(
      byte[] cardChallenge, byte[] currentPin, byte[] newPin, byte kif, byte kvc) {
    return new byte[0];
  }

  @Override
  public byte[] generateCardKey(
      byte[] cardChallenge,
      byte issuerKeyKif,
      byte issuerKeyKvc,
      byte targetKeyKif,
      byte targetKeyKvc) {
    return new byte[0];
  }
}
