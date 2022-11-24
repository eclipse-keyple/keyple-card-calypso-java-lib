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

interface SymmetricCryptoSecuritySetting extends SecuritySetting<SymmetricCryptoSecuritySetting> {

  SymmetricCryptoSecuritySetting setCryptoService(SymmetricCryptoService cryptoService);

  SymmetricCryptoSecuritySetting enableEarlyMutualAuthentication();

  SymmetricCryptoSecuritySetting enableRatificationMechanism();

  SymmetricCryptoSecuritySetting enablePinPlainTransmission();

  SymmetricCryptoSecuritySetting enableSvLoadAndDebitLog();

  SymmetricCryptoSecuritySetting authorizeSvNegativeBalance();

  SymmetricCryptoSecuritySetting forceRegularMode();

  SymmetricCryptoSecuritySetting assignKif(WriteAccessLevel writeAccessLevel, byte kvc, byte kif);

  SymmetricCryptoSecuritySetting assignDefaultKif(WriteAccessLevel writeAccessLevel, byte kif);

  SymmetricCryptoSecuritySetting assignDefaultKvc(WriteAccessLevel writeAccessLevel, byte kvc);

  SymmetricCryptoSecuritySetting addAuthorizedSessionKey(byte kif, byte kvc);

  SymmetricCryptoSecuritySetting addAuthorizedSvKey(byte kif, byte kvc);

  SymmetricCryptoSecuritySetting setPinVerificationCipheringKey(byte kif, byte kvc);

  SymmetricCryptoSecuritySetting setPinModificationCipheringKey(byte kif, byte kvc);
}
