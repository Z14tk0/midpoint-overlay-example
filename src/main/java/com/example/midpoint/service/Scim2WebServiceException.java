/**
 * Copyright: DAASI International GmbH 2020-2020. All rights reserved.
 *
 * This is Open Source Software
 * License: Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 *
 * Author: Tamim Ziai DAASI International GmbH, www.daasi.de
 * For questions please mail to info@daasi.de
 */
package com.example.midpoint.service;

import jakarta.ws.rs.core.Response.StatusType;

public abstract class Scim2WebServiceException extends Exception {

	private static final long serialVersionUID = -5108622963938676587L;

	private final StatusType status;

	private final String scimDetail;

	public Scim2WebServiceException(StatusType status, String message, String scimDetail, Throwable cause) {
		super(message, cause);
		this.status = status;
		this.scimDetail = scimDetail;
	}

	public Scim2WebServiceException(StatusType status, String message, String scimDetail) {
		super(message);
		this.status = status;
		this.scimDetail = scimDetail;
	}

	StatusType getStatus() {
		return this.status;
	}

	String getScimDetail() {
		return this.scimDetail;
	}

	@Override
	public String getMessage() {
		StringBuilder sb = new StringBuilder();
		if( getScimDetail() != null ) {
			sb.append( getScimDetail() ).append( " : " );
		}
		return sb.append( super.getMessage() ).toString();
	}

	@Override
	public String toString() {
		return new StringBuilder( getMessage().length() + 25 ).append( status ).append( super.toString() ).toString();
	}

}
