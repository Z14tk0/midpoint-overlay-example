/**
 * Copyright: DAASI International GmbH 2020-2020. All rights reserved.
 *
 * This is Open Source Software
 * License: Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 *
 * Author: Tamim Ziai DAASI International GmbH, www.daasi.de
 * For questions please mail to info@daasi.de
 */
package com.example.midpoint.service.exception;

import jakarta.ws.rs.core.Response.Status.Family;
import jakarta.ws.rs.core.Response.StatusType;

public class UnprocessableEntryStatus implements StatusType {

  @Override
  public int getStatusCode() {
    return 422;
  }

  @Override
  public Family getFamily() {
    return Family.CLIENT_ERROR;
  }

  @Override
  public String getReasonPhrase() {
    return "Unprocessable Entity";
  }

}
