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

interface SymmetricCryptoServiceSpi {
  void setKeyDiversifier(byte[] keyDiversifier);

  byte[] initTerminalSecureSessionContext();

  void initTerminalSessionMac(byte[] openSecureSessionDataOut, byte kif, byte kvc);

  byte[] updateTerminalSessionMac(byte[] cardApdu);

  byte[] finalizeTerminalSessionMac();

  byte[] generateTerminalSessionMac();

  void activateEncryption();

  void deactivateEncryption();

  boolean verifyCardSessionMac(byte[] cardSessionMac);

  void generateSvCommandSecurityData(SvCommandSecurityData svCommandSecurityData);

  boolean verifyCardSvMac(byte[] cardSvMac);

  byte[] cipherPinForPresentation(byte[] cardChallenge, byte[] pin, byte kif, byte kvc);

  byte[] cipherPinForModification(
      byte[] cardChallenge, byte[] currentPin, byte[] newPin, byte kif, byte kvc);

  byte[] generateCardKey(
      byte[] cardChallenge,
      byte issuerKeyKif,
      byte issuerKeyKvc,
      byte targetKeyKif,
      byte targetKeyKvc);
}
