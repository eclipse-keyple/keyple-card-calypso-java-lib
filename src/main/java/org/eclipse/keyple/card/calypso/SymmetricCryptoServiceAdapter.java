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
import java.util.Arrays;
import java.util.List;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureVerificationData;
import org.calypsonet.terminal.calypso.transaction.SamRevokedException;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;

class SymmetricCryptoServiceAdapter implements SymmetricCryptoService, SymmetricCryptoServiceSpi {
  private static final String MSG_INPUT_OUTPUT_DATA = "input/output data";
  private static final String MSG_SIGNATURE_SIZE = "signature size";
  private static final String MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8 =
      "key diversifier size is in range [1..8]";

  /* Final fields */
  private final ProxyReaderApi samReader;
  private final CalypsoSamAdapter sam;
  private final SymmetricKeySecuritySettingAdapter securitySetting;
  private final boolean isCardSupportingExtendedMode;
  private final List<AbstractSamCommand> samCommands = new ArrayList<AbstractSamCommand>();

  /* Dynamic fields */
  private byte[] keyDiversifier;
  private byte[] currentKeyDiversifier;
  private final List<byte[]> transactionAuditData;

  SymmetricCryptoServiceAdapter(
      ProxyReaderApi samReader,
      CalypsoSamAdapter sam,
      SymmetricKeySecuritySettingAdapter symmetricKeySecuritySetting,
      boolean isCardSupportingExtendedMode,
      List<byte[]> transactionAuditData) {
    this.samReader = samReader;
    this.sam = sam;
    this.securitySetting = symmetricKeySecuritySetting;
    this.isCardSupportingExtendedMode = isCardSupportingExtendedMode;
    this.transactionAuditData = transactionAuditData;
  }

  @Override
  public void setKeyDiversifier(byte[] keyDiversifier) {
    this.keyDiversifier = keyDiversifier;
  }

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

  void processCommands() {}

  /**
   * (private)<br>
   * Prepares a "SelectDiversifier" command using the current key diversifier.
   *
   * @return The current instance.
   */
  private void prepareSelectDiversifier() {
    samCommands.add(new CmdSamSelectDiversifier(sam, currentKeyDiversifier));
  }

  /**
   * (package-private)<br>
   * Prepares a "SelectDiversifier" command using a specific or the default key diversifier if it is
   * not already selected.
   *
   * @param specificKeyDiversifier The specific key diversifier (optional).
   * @since 2.2.0
   */
  final void prepareSelectDiversifierIfNeeded(byte[] specificKeyDiversifier) {
    if (specificKeyDiversifier != null) {
      if (!Arrays.equals(specificKeyDiversifier, currentKeyDiversifier)) {
        currentKeyDiversifier = specificKeyDiversifier;
        prepareSelectDiversifier();
      }
    } else {
      prepareSelectDiversifierIfNeeded();
    }
  }

  /**
   * (package-private)<br>
   * Prepares a "SelectDiversifier" command using the default key diversifier if it is not already
   * selected.
   *
   * @since 2.2.0
   */
  final void prepareSelectDiversifierIfNeeded() {
    if (!Arrays.equals(currentKeyDiversifier, keyDiversifier)) {
      currentKeyDiversifier = keyDiversifier;
      prepareSelectDiversifier();
    }
  }

  void prepareComputeSignature(CommonSignatureComputationData data) {

    if (data instanceof BasicSignatureComputationDataAdapter) {
      // Basic signature
      BasicSignatureComputationDataAdapter dataAdapter =
          (BasicSignatureComputationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "data to sign")
          .isInRange(dataAdapter.getData().length, 1, 208, "length of data to sign")
          .isTrue(
              dataAdapter.getData().length % 8 == 0, "length of data to sign is a multiple of 8")
          .isInRange(dataAdapter.getSignatureSize(), 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      samCommands.add(new CmdSamDataCipher(sam, dataAdapter, null));

    } else if (data instanceof TraceableSignatureComputationDataAdapter) {
      // Traceable signature
      TraceableSignatureComputationDataAdapter dataAdapter =
          (TraceableSignatureComputationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "data to sign")
          .isInRange(
              dataAdapter.getData().length,
              1,
              dataAdapter.isSamTraceabilityMode() ? 206 : 208,
              "length of data to sign")
          .isInRange(dataAdapter.getSignatureSize(), 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              !dataAdapter.isSamTraceabilityMode()
                  || (dataAdapter.getTraceabilityOffset() >= 0
                      && dataAdapter.getTraceabilityOffset()
                          <= ((dataAdapter.getData().length * 8)
                              - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))),
              "traceability offset is in range [0.."
                  + ((dataAdapter.getData().length * 8)
                      - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))
                  + "]")
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      samCommands.add(new CmdSamPsoComputeSignature(sam, dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'BasicSignatureComputationDataAdapter' or 'TraceableSignatureComputationDataAdapter'");
    }
  }

  void prepareVerifySignature(CommonSignatureVerificationData data) {
    if (data instanceof BasicSignatureVerificationDataAdapter) {
      // Basic signature
      BasicSignatureVerificationDataAdapter dataAdapter =
          (BasicSignatureVerificationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "signed data to verify")
          .isInRange(dataAdapter.getData().length, 1, 208, "length of signed data to verify")
          .isTrue(
              dataAdapter.getData().length % 8 == 0, "length of data to verify is a multiple of 8")
          .notNull(dataAdapter.getSignature(), "signature")
          .isInRange(dataAdapter.getSignature().length, 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      samCommands.add(new CmdSamDataCipher(sam, null, dataAdapter));

    } else if (data instanceof TraceableSignatureVerificationDataAdapter) {
      // Traceable signature
      TraceableSignatureVerificationDataAdapter dataAdapter =
          (TraceableSignatureVerificationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "signed data to verify")
          .isInRange(
              dataAdapter.getData().length,
              1,
              dataAdapter.isSamTraceabilityMode() ? 206 : 208,
              "length of signed data to verify")
          .notNull(dataAdapter.getSignature(), "signature")
          .isInRange(dataAdapter.getSignature().length, 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              !dataAdapter.isSamTraceabilityMode()
                  || (dataAdapter.getTraceabilityOffset() >= 0
                      && dataAdapter.getTraceabilityOffset()
                          <= ((dataAdapter.getData().length * 8)
                              - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))),
              "traceability offset is in range [0.."
                  + ((dataAdapter.getData().length * 8)
                      - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))
                  + "]")
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      // Check SAM revocation status if requested.
      if (dataAdapter.isSamRevocationStatusVerificationRequested()) {
        Assert.getInstance()
            .notNull(securitySetting, "security settings")
            .notNull(securitySetting.getSamRevocationServiceSpi(), "SAM revocation service");

        // Extract the SAM serial number and the counter value from the data.
        byte[] samSerialNumber =
            ByteArrayUtil.extractBytes(
                dataAdapter.getData(),
                dataAdapter.getTraceabilityOffset(),
                dataAdapter.isPartialSamSerialNumber() ? 3 : 4);

        int samCounterValue =
            ByteArrayUtil.extractInt(
                ByteArrayUtil.extractBytes(
                    dataAdapter.getData(),
                    dataAdapter.getTraceabilityOffset()
                        + (dataAdapter.isPartialSamSerialNumber() ? 3 * 8 : 4 * 8),
                    3),
                0,
                3,
                false);

        // Is SAM revoked ?
        if (securitySetting
            .getSamRevocationServiceSpi()
            .isSamRevoked(samSerialNumber, samCounterValue)) {
          throw new SamRevokedException(
              String.format(
                  "SAM with serial number '%s' and counter value '%d' is revoked.",
                  HexUtil.toHex(samSerialNumber), samCounterValue));
        }
      }

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      samCommands.add(new CmdSamPsoVerifySignature(sam, dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'CommonSignatureVerificationDataAdapter'");
    }
  }
}
