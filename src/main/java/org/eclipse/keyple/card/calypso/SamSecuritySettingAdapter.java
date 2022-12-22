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

import org.calypsonet.terminal.calypso.transaction.SamSecuritySetting;

/**
 * Implementation of {@link SamSecuritySetting}.
 *
 * @since 2.2.0
 * @deprecated
 */
@Deprecated
final class SamSecuritySettingAdapter extends CommonSecuritySettingAdapter<SamSecuritySetting>
    implements SamSecuritySetting {}
