/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2022, Connect2id Ltd.
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

package com.nimbusds.jose.jwk.source;

import java.util.ArrayList;
import java.util.List;

public class ThreadHelper extends Thread {

	private Object lock = new Object();

	private final List<Runnable> runnables = new ArrayList<>();

	@Override
	public void run() {
		int i = 0;
		try {
			while (i < runnables.size()) {
				runnables.get(i).run();

				i++;
			}
		} catch (Exception e) {
			// ignore, run rest without locking
			while (i < runnables.size()) {
				runnables.get(i).run();

				i++;
			}
		}
	}

	public void next() {
		synchronized (lock) {
			lock.notifyAll();
		}
	}

	public void close() {
		synchronized (lock) {
			lock.notifyAll();
		}

		this.interrupt();
	}

	public void begin() {
		start();
		while (getState() != State.WAITING && getState() != State.TERMINATED) {
			Thread.yield();
		}
	}

	public ThreadHelper addRun(Runnable runnable) {
		runnables.add(runnable);

		return this;
	}

	public ThreadHelper addPause() {
		runnables.add(new Runnable() {

			@Override
			public void run() {
				synchronized (lock) {
					try {
						lock.wait();
					} catch (InterruptedException e) {
						// do nothing
					}
				}
			}
		});

		return this;
	}
}
