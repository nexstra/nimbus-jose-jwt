/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.jwk.source.log;

import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class AbstractJWKSetSourceLogger {

	protected final Level level;
	protected final Logger logger;

	public AbstractJWKSetSourceLogger(final Level level, final Logger logger) {
		this.level = level;
		this.logger = logger;
	}
}