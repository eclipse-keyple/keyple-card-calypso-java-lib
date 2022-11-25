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

class SvCommandSecurityDataApiAdapter implements SvCommandSecurityDataApi {

  private byte[] svGetRequest;
  private byte[] svGetResponse;
  private byte[] svCommandPartialRequest;
  private byte[] serialNumber;
  private byte[] transactionNumber;
  private byte[] terminalChallenge;
  private byte[] terminalSvMac;

  @Override
  public byte[] getSvGetRequest() {
    return svGetRequest;
  }

  @Override
  public byte[] getSvGetResponse() {
    return svGetResponse;
  }

  @Override
  public byte[] getSvCommandPartialRequest() {
    return svCommandPartialRequest;
  }

  @Override
  public SvCommandSecurityDataApiAdapter setSerialNumber(byte[] serialNumber) {
    this.serialNumber = serialNumber;
    return this;
  }

  @Override
  public SvCommandSecurityDataApiAdapter setTransactionNumber(byte[] transactionNumber) {
    this.transactionNumber = transactionNumber;
    return this;
  }

  @Override
  public SvCommandSecurityDataApiAdapter setTerminalChallenge(byte[] terminalChallenge) {
    this.terminalChallenge = terminalChallenge;
    return this;
  }

  @Override
  public SvCommandSecurityDataApiAdapter setTerminalSvMac(byte[] terminalSvMac) {
    this.terminalSvMac = terminalSvMac;
    return this;
  }

  SvCommandSecurityDataApi setSvGetRequest(byte[] svGetRequest) {
    this.svGetRequest = svGetRequest;
    return this;
  }

  SvCommandSecurityDataApi setSvGetResponse(byte[] svGetResponse) {
    this.svGetResponse = svGetResponse;
    return this;
  }

  SvCommandSecurityDataApi setSvCommandPartialRequest(byte[] svCommandPartialRequest) {
    this.svCommandPartialRequest = svCommandPartialRequest;
    return this;
  }

  byte[] getSerialNumber() {
    return serialNumber;
  }

  byte[] getTransactionNumber() {
    return transactionNumber;
  }

  byte[] getTerminalChallenge() {
    return terminalChallenge;
  }

  byte[] getTerminalSvMac() {
    return terminalSvMac;
  }
}
