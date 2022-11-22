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

class SvCommandSecurityDataAdapter implements SvCommandSecurityData {

  @Override
  public SvCommandSecurityData setSvGetRequest(byte[] svGetRequest) {
    return null;
  }

  @Override
  public SvCommandSecurityData setSvGetResponse(byte[] svGetResponse) {
    return null;
  }

  @Override
  public SvCommandSecurityData setSvCommandRequest(byte[] svCommandRequest) {
    return null;
  }

  @Override
  public byte[] getSerialNumber() {
    return new byte[0];
  }

  @Override
  public byte[] getTransactionNumber() {
    return new byte[0];
  }

  @Override
  public byte[] getTerminalChallenge() {
    return new byte[0];
  }

  @Override
  public byte[] getTerminalSvMac() {
    return new byte[0];
  }
}
