/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.calypso;

import org.eclipse.keyple.calypso.sam.SamRevision;
import org.eclipse.keyple.core.service.selection.spi.CardSelector;

/**
 * (package-private)<br>
 * The {@link CalypsoSamCardSelector} class extends {@link CardSelector} to handle specific Calypso
 * SAM needs such as model identification.
 *
 * @since 2.0
 */
final class CalypsoSamCardSelector extends CardSelector {

  private final SamRevision targetSamRevision;
  private final byte[] unlockData;

  /** Private constructor */
  private CalypsoSamCardSelector(CalypsoSamCardSelectorBuilder builder) {
    setAtrFilter(new AtrFilter(builder.atrRegex));
    this.targetSamRevision = builder.targetSamRevision;
    this.unlockData = builder.unlockData;
  }

  /**
   * CalypsoSamCardSelectorBuilder of {@link CalypsoSamCardSelector}
   *
   * @since 2.0
   */
  public static final class CalypsoSamCardSelectorBuilder {

    private SamRevision targetSamRevision;
    private String serialNumber;
    String atrRegex;
    private byte[] unlockData;

    /**
     * Creates an instance.
     *
     * @since 2.0
     */
    public CalypsoSamCardSelectorBuilder() {
      super();
    }

    /**
     * Sets the SAM revision
     *
     * @param targetSamRevision the {@link SamRevision} of the targeted SAM
     * @return the builder instance
     * @since 2.0
     */
    public CalypsoSamCardSelectorBuilder setSamRevision(SamRevision targetSamRevision) {
      this.targetSamRevision = targetSamRevision;
      return this;
    }

    /**
     * Sets the SAM serial number regex
     *
     * @param serialNumber the serial number of the targeted SAM as regex
     * @return the builder instance
     * @since 2.0
     */
    public CalypsoSamCardSelectorBuilder setSerialNumber(String serialNumber) {
      this.serialNumber = serialNumber;
      return this;
    }

    /**
     * Sets the unlock data
     *
     * @param unlockData a byte array containing the unlock data (8 or 16 bytes)
     * @return the builder instance
     * @throws IllegalArgumentException if the provided buffer size is not 8 or 16
     * @since 2.0
     */
    public CalypsoSamCardSelectorBuilder setUnlockData(byte[] unlockData) {
      if (unlockData == null || (unlockData.length != 8 && unlockData.length != 16)) {
        throw new IllegalArgumentException("Bad unlock data length. Should be 8 or 16 bytes.");
      }
      this.unlockData = unlockData;
      return this;
    }

    /**
     * Build a new {@code SamSelector}.
     *
     * @return a new instance
     * @since 2.0
     */
    public CalypsoSamCardSelector build() {
      String snRegex;
      /* check if serialNumber is defined */
      if (serialNumber == null || serialNumber.isEmpty()) {
        /* match all serial numbers */
        snRegex = ".{8}";
      } else {
        /* match the provided serial number (could be a regex substring) */
        snRegex = serialNumber;
      }
      /*
       * build the final Atr regex according to the SAM subtype and serial number if any.
       *
       * The header is starting with 3B, its total length is 4 or 6 bytes (8 or 10 hex digits)
       */
      if (targetSamRevision != null) {
        switch (targetSamRevision) {
          case C1:
          case S1D:
          case S1E:
            this.atrRegex =
                "3B(.{6}|.{10})805A..80"
                    + targetSamRevision.getApplicationTypeMask()
                    + "20.{4}"
                    + snRegex
                    + "829000";
            break;
          default:
            throw new IllegalArgumentException("Unknown SAM subtype.");
        }
      } else {
        /* match any ATR */
        this.atrRegex = ".*";
      }
      return new CalypsoSamCardSelector(this);
    }
  }

  /**
   * Gets a new builder.
   *
   * @return a new builder instance
   * @since 2.0
   */
  public static CalypsoSamCardSelectorBuilder builder() {
    return new CalypsoSamCardSelectorBuilder();
  }

  /**
   * Gets the specified SAM revision.
   *
   * @return null if no SAM revision has been set.
   * @since 2.0
   */
  public SamRevision getTargetSamRevision() {
    return targetSamRevision;
  }

  /**
   * Gets the SAM unlock data
   *
   * @return a byte array containing the unlock data or null if the unlock data is not set
   * @since 2.0
   */
  public byte[] getUnlockData() {
    return unlockData;
  }
}
