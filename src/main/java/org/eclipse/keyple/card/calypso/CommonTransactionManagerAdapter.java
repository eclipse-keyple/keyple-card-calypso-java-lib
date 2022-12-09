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

import java.util.ArrayList;
import java.util.List;
import org.calypsonet.terminal.calypso.transaction.CommonSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.CommonTransactionManager;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardResponseApi;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.calypsonet.terminal.reader.selection.spi.SmartCard;
import org.eclipse.keyple.core.util.json.JsonUtil;

/**
 * Implementation of {@link CommonTransactionManager}.
 *
 * @param <T> The type of the lowest level child object.
 * @param <S> The type of the lowest level child object of the associated {@link
 *     CommonSecuritySetting}.
 * @since 2.2.0
 */
abstract class CommonTransactionManagerAdapter<
        T extends CommonTransactionManager<T, S>, S extends CommonSecuritySetting<S>>
    implements CommonTransactionManager<T, S> {

  /* Prefix/suffix used to compose exception messages */
  static final String MSG_SAM_READER_COMMUNICATION_ERROR =
      "A communication error with the SAM reader occurred ";
  static final String MSG_SAM_COMMUNICATION_ERROR = "A communication error with the SAM occurred ";
  static final String MSG_SAM_COMMAND_ERROR = "A SAM command error occurred ";

  static final String MSG_WHILE_TRANSMITTING_COMMANDS = "while transmitting commands.";

  /* Final fields */
  private final SmartCard targetSmartCard; // Target card or SAM
  private final CommonSecuritySettingAdapter<?> securitySetting;
  private final List<byte[]> transactionAuditData;

  /**
   * Creates a new instance.
   *
   * @param targetSmartCard The target smartcard provided by the selection process.
   * @param securitySetting The security settings (optional).
   * @param transactionAuditData The original transaction data to fill (optional).
   * @since 2.2.0
   */
  CommonTransactionManagerAdapter(
      SmartCard targetSmartCard,
      CommonSecuritySettingAdapter<?> securitySetting,
      List<byte[]> transactionAuditData) {
    this.targetSmartCard = targetSmartCard;
    this.securitySetting = securitySetting;
    this.transactionAuditData =
        transactionAuditData != null ? transactionAuditData : new ArrayList<byte[]>();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public final List<byte[]> getTransactionAuditData() {
    // CL-CSS-INFODATA.1
    return transactionAuditData;
  }

  /**
   * Saves the provided exchanged APDU commands in the list of transaction audit data.
   *
   * @param cardRequest The card request.
   * @param cardResponse The associated card response.
   * @since 2.1.1
   */
  void saveTransactionAuditData(CardRequestSpi cardRequest, CardResponseApi cardResponse) {
    if (cardResponse != null) {
      List<ApduRequestSpi> requests = cardRequest.getApduRequests();
      List<ApduResponseApi> responses = cardResponse.getApduResponses();
      for (int i = 0; i < responses.size(); i++) {
        transactionAuditData.add(requests.get(i).getApdu());
        transactionAuditData.add(responses.get(i).getApdu());
      }
    }
  }

  /**
   * Saves the provided exchanged APDU commands in the provided list of transaction audit data.
   *
   * @param cardRequest The card request.
   * @param cardResponse The associated card response.
   * @param transactionAuditData The list to complete.
   * @since 2.1.1
   */
  static void saveTransactionAuditData(
      CardRequestSpi cardRequest, CardResponseApi cardResponse, List<byte[]> transactionAuditData) {
    if (cardResponse != null) {
      List<ApduRequestSpi> requests = cardRequest.getApduRequests();
      List<ApduResponseApi> responses = cardResponse.getApduResponses();
      for (int i = 0; i < responses.size(); i++) {
        transactionAuditData.add(requests.get(i).getApdu());
        transactionAuditData.add(responses.get(i).getApdu());
      }
    }
  }

  /**
   * Returns a string representation of the transaction audit data.
   *
   * @return A not empty string.
   */
  final String getTransactionAuditDataAsString() {
    StringBuilder sb = new StringBuilder();
    sb.append("\nTransaction audit JSON data: {");
    sb.append("\"targetSmartCard\":").append(targetSmartCard.toString()).append(",");
    if (securitySetting != null && securitySetting.getControlSam() != null) {
      sb.append("\"controlSam\":").append(securitySetting.getControlSam().toString()).append(",");
    }
    sb.append("\"apdus\":").append(JsonUtil.toJson(transactionAuditData));
    sb.append("}");
    return sb.toString();
  }
}
