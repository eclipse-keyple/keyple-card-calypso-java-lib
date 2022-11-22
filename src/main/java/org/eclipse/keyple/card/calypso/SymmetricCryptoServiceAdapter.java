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
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureVerificationData;
import org.calypsonet.terminal.calypso.transaction.SamRevokedException;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.eclipse.keyple.core.util.ApduUtil;
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
  private byte[] defaultKeyDiversifier;
  private byte[] currentKeyDiversifier;
  private final List<byte[]> transactionAuditData;
  private DigestManager digestManager;

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
  public void setDefaultKeyDiversifier(byte[] keyDiversifier) {
    this.defaultKeyDiversifier = keyDiversifier;
  }

  @Override
  public byte[] initTerminalSecureSessionContext() {
    prepareSelectDiversifierIfNeeded();
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
    if (!Arrays.equals(currentKeyDiversifier, defaultKeyDiversifier)) {
      currentKeyDiversifier = defaultKeyDiversifier;
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

  /**
   * (private)<br>
   * The manager of the digest session.
   */
  private class DigestManager {

    private final byte[] openSecureSessionDataOut;
    private final byte sessionKif;
    private final byte sessionKvc;
    private final boolean isSessionEncrypted;
    private final boolean isVerificationMode;
    private final List<byte[]> cardApdus = new ArrayList<byte[]>();
    private boolean isDigestInitDone;

    /**
     * (private)<br>
     * Creates a new digest manager.
     *
     * @param openSecureSessionDataOut The data out of the "Open Secure Session" card command.
     * @param kif The KIF to use.
     * @param kvc The KVC to use.
     * @param isSessionEncrypted True if the session is encrypted.
     * @param isVerificationMode True if the verification mode is enabled.
     */
    private DigestManager(
        byte[] openSecureSessionDataOut,
        byte kif,
        byte kvc,
        boolean isSessionEncrypted,
        boolean isVerificationMode) {
      this.openSecureSessionDataOut = openSecureSessionDataOut;
      this.sessionKif = kif;
      this.sessionKvc = kvc;
      this.isSessionEncrypted = isSessionEncrypted;
      this.isVerificationMode = isVerificationMode;
    }

    /**
     * (private)<br>
     * Add one or more exchanged card APDUs to the buffer.
     *
     * @param requests The requests.
     * @param responses The associated responses.
     * @param startIndex The index of the request from which to start.
     */
    private void updateSession(
        List<ApduRequestSpi> requests, List<ApduResponseApi> responses, int startIndex) {
      for (int i = startIndex; i < requests.size(); i++) {
        // If the request is of case4 type, LE must be excluded from the digest computation. In this
        // case, we remove here the last byte of the command buffer.
        // CL-C4-MAC.1
        ApduRequestSpi request = requests.get(i);
        cardApdus.add(
            ApduUtil.isCase4(request.getApdu())
                ? Arrays.copyOfRange(request.getApdu(), 0, request.getApdu().length - 1)
                : request.getApdu());
        ApduResponseApi response = responses.get(i);
        cardApdus.add(response.getApdu());
      }
    }

    /**
     * (private)<br>
     * Prepares all pending digest commands.
     */
    private void prepareCommands() {
      // Prepare the "Digest Init" command if not already done.
      if (!isDigestInitDone) {
        prepareDigestInit();
      }
      // Prepare the "Digest Update" commands and flush the buffer.
      prepareDigestUpdate();
      cardApdus.clear();
      // Prepare the "Digest Close" command.
      prepareDigestClose();
    }

    /**
     * (private)<br>
     * Prepares the "Digest Init" SAM command.
     */
    private void prepareDigestInit() {
      // CL-SAM-DINIT.1
      samCommands.add(
          new CmdSamDigestInit(
              sam,
              isVerificationMode,
              isCardSupportingExtendedMode && !securitySetting.isRegularModeRequired(),
              sessionKif,
              sessionKvc,
              openSecureSessionDataOut));
      isDigestInitDone = true;
    }

    /**
     * (private)<br>
     * Prepares the "Digest Update" SAM command.
     */
    private void prepareDigestUpdate() {
      if (cardApdus.isEmpty()) {
        return;
      }
      // CL-SAM-DUPDATE.1
      if (sam.getProductType() == CalypsoSam.ProductType.SAM_C1) {
        // Digest Update Multiple
        // Construct list of DataIn
        List<byte[]> digestDataList = new ArrayList<byte[]>(1);
        byte[] buffer = new byte[255];
        int i = 0;
        for (byte[] cardApdu : cardApdus) {
          /*
           * The maximum buffer length of the "Digest Update Multiple" SAM command is set to 230
           * bytes instead of the 254 theoretically allowed by the SAM in order to be compatible
           * with certain unpredictable applications (e.g. 237 for the Hoplink application).
           */
          if (i + cardApdu.length > 230) {
            // Copy buffer to digestDataList and reset buffer
            digestDataList.add(Arrays.copyOf(buffer, i));
            i = 0;
          }
          // Add [length][apdu] to current buffer
          buffer[i++] = (byte) cardApdu.length;
          System.arraycopy(cardApdu, 0, buffer, i, cardApdu.length);
          i += cardApdu.length;
        }
        // Copy buffer to digestDataList
        digestDataList.add(Arrays.copyOf(buffer, i));
        // Add commands
        for (byte[] dataIn : digestDataList) {
          samCommands.add(new CmdSamDigestUpdateMultiple(sam, dataIn));
        }
      } else {
        // Digest Update (simple)
        for (byte[] cardApdu : cardApdus) {
          samCommands.add(new CmdSamDigestUpdate(sam, isSessionEncrypted, cardApdu));
        }
      }
    }

    /**
     * (private)<br>
     * Prepares the "Digest Close" SAM command.
     */
    private void prepareDigestClose() {
      // CL-SAM-DCLOSE.1
      samCommands.add(
          new CmdSamDigestClose(
              sam,
              isCardSupportingExtendedMode && !securitySetting.isRegularModeRequired() ? 8 : 4));
    }
  }
}
