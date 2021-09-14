/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import java.lang.reflect.Type;

/**
 * (package-private)<br>
 * Deserializer of a {@link org.calypsonet.terminal.calypso.card.ElementaryFile}.
 *
 * @since 2.0.0
 */
final class ElementaryFileJsonDeserializerAdapter
    implements JsonDeserializer<ElementaryFileAdapter> {

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public ElementaryFileAdapter deserialize(
      JsonElement json, Type typeOfT, JsonDeserializationContext context)
      throws JsonParseException {
    return context.deserialize(json, ElementaryFileAdapter.class);
  }
}
