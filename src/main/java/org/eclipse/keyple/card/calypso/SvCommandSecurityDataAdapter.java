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

  private byte[] svGetRequest;
  private byte[] svGetResponse;
  private byte[] svCommandRequest;
  private byte[] serialNumber;
  private byte[] transactionNumber;
  private byte[] terminalChallenge;
  private byte[] terminalSvMac;

  @Override
  public SvCommandSecurityData setSvGetRequest(byte[] svGetRequest) {
    this.svGetRequest = svGetRequest;
    return this;
  }

  @Override
  public SvCommandSecurityData setSvGetResponse(byte[] svGetResponse) {
    this.svGetResponse = svGetResponse;
    return this;
  }

  @Override
  public SvCommandSecurityData setSvCommandRequest(byte[] svCommandRequest) {
    this.svCommandRequest = svCommandRequest;
    return this;
  }

  @Override
  public byte[] getSerialNumber() {
    return serialNumber;
  }

  @Override
  public byte[] getTransactionNumber() {
    return transactionNumber;
  }

  @Override
  public byte[] getTerminalChallenge() {
    return terminalChallenge;
  }

  @Override
  public byte[] getTerminalSvMac() {
    return terminalSvMac;
  }

  public SvCommandSecurityDataAdapter setSerialNumber(byte[] serialNumber) {
    this.serialNumber = serialNumber;
    return this;
  }

  public SvCommandSecurityDataAdapter setTransactionNumber(byte[] transactionNumber) {
    this.transactionNumber = transactionNumber;
    return this;
  }

  public SvCommandSecurityDataAdapter setTerminalChallenge(byte[] terminalChallenge) {
    this.terminalChallenge = terminalChallenge;
    return this;
  }

  public SvCommandSecurityDataAdapter setTerminalSvMac(byte[] terminalSvMac) {
    this.terminalSvMac = terminalSvMac;
    return this;
  }

  byte[] getSvGetRequest() {
    return svGetRequest;
  }

  byte[] getSvGetResponse() {
    return svGetResponse;
  }

  byte[] getSvCommandRequest() {
    return svCommandRequest;
  }
}
