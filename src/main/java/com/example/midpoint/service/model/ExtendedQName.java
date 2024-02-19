/**
 * Copyright: DAASI International GmbH 2020-2020. All rights reserved.
 *
 * This is Open Source Software
 * License: Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 *
 * Author: Tamim Ziai DAASI International GmbH, www.daasi.de
 * For questions please mail to info@daasi.de
 */
package com.example.midpoint.service.model;

import javax.xml.namespace.QName;

public class ExtendedQName extends QName {

	private static final long serialVersionUID = 1L;

	private boolean isUnique = false;

	public ExtendedQName(String localPart) {
		super(localPart);
	}

	public ExtendedQName(String namespaceURI, String localPart) {
		super(namespaceURI, localPart);
	}

	public ExtendedQName(String namespaceURI, String localPart, boolean unique) {
		super(namespaceURI, localPart);
		this.setUnique(unique);
	}

	public boolean isUnique() {
		return isUnique;
	}

	public void setUnique(boolean isUnique) {
		this.isUnique = isUnique;
	}

}
