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

interface SymmetricKeySecuritySetting extends SecuritySetting<SymmetricKeySecuritySetting> {

  SymmetricKeySecuritySetting setCryptoService(SymmetricCryptoService cryptoService);

  SymmetricKeySecuritySetting enableEarlyMutualAuthentication();

  SymmetricKeySecuritySetting enableRatificationMechanism();

  SymmetricKeySecuritySetting enablePinPlainTransmission();

  SymmetricKeySecuritySetting enableSvLoadAndDebitLog();

  SymmetricKeySecuritySetting authorizeSvNegativeBalance();

  SymmetricKeySecuritySetting forceRegularMode();

  SymmetricKeySecuritySetting assignKif(WriteAccessLevel writeAccessLevel, byte kvc, byte kif);

  SymmetricKeySecuritySetting assignDefaultKif(WriteAccessLevel writeAccessLevel, byte kif);

  SymmetricKeySecuritySetting assignDefaultKvc(WriteAccessLevel writeAccessLevel, byte kvc);

  SymmetricKeySecuritySetting addAuthorizedSessionKey(byte kif, byte kvc);

  SymmetricKeySecuritySetting addAuthorizedSvKey(byte kif, byte kvc);

  SymmetricKeySecuritySetting setPinVerificationCipheringKey(byte kif, byte kvc);

  SymmetricKeySecuritySetting setPinModificationCipheringKey(byte kif, byte kvc);
}
