// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.webauthn.gaedemo.servlets;

import com.google.appengine.api.users.UserService;
import com.google.appengine.api.users.UserServiceFactory;
import com.google.common.io.BaseEncoding;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.webauthn.gaedemo.exceptions.ResponseException;
import com.google.webauthn.gaedemo.objects.AuthenticatorAssertionResponse;
import com.google.webauthn.gaedemo.objects.PublicKeyCredential;
import com.google.webauthn.gaedemo.server.AndroidSafetyNetServer;
import com.google.webauthn.gaedemo.server.PackedServer;
import com.google.webauthn.gaedemo.server.PublicKeyCredentialResponse;
import com.google.webauthn.gaedemo.server.Server;
import com.google.webauthn.gaedemo.server.U2fServer;
import com.google.webauthn.gaedemo.storage.Credential;



import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.fhirblocks.core.model.csi.CSI;
import org.fhirblocks.core.model.csi.CsiModelException;
import org.fhirblocks.merlot.authtools.AuthorizationException;
import org.fhirblocks.merlot.authtools.FhirBlocksAuthorizationEngine;
import org.fhirblocks.merlot.authtools.model.ClientAuthorization;
import org.fhirblocks.merlot.blockchain.exceptions.CsiException;
import org.fhirblocks.merlot.blockchain.exceptions.KeySpaceException;
import org.fhirblocks.merlot.blockchain.handler.CsiHandler;
import org.json.JSONException;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.LinkedList;
import java.util.UUID;
import java.util.logging.Logger;


public class FinishGetAssertion extends HttpServlet {
  private static final long serialVersionUID = 1L;
  private final UserService userService = UserServiceFactory.getUserService();
  
  private static final Logger Log = Logger.getLogger(FinishGetAssertion.class.getName());


  public FinishGetAssertion() {

  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    doPost(request, response);
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String currentUser = userService.getCurrentUser().getEmail();
    String data = request.getParameter("data");
    String session = request.getParameter("session");

    String credentialId = null;
    String type = null;
    JsonElement assertionJson = null;

    try {
      JsonObject json = new JsonParser().parse(data).getAsJsonObject();
      JsonElement idJson = json.get("id");
      if (idJson != null) {
        credentialId = idJson.getAsString();
      }
      JsonElement typeJson = json.get("type");
      if (typeJson != null) {
        type = typeJson.getAsString();
      }
      assertionJson = json.get("response");
      if (assertionJson == null) {
        throw new ServletException("Missing element 'response'");
      }
    } catch (IllegalStateException e) {
      throw new ServletException("Passed data not a json object");
    } catch (ClassCastException e) {
      throw new ServletException("Invalid input");
    } catch (JsonParseException e) {
      throw new ServletException("Input not valid json");
    }

    AuthenticatorAssertionResponse assertion = null;
    try {
      assertion = new AuthenticatorAssertionResponse(assertionJson);
    } catch (ResponseException e) {
      throw new ServletException(e.toString());
    }

    // Recoding of credential ID is needed, because the ID from HTTP servlet request doesn't support
    // padding.
    String credentialIdRecoded = BaseEncoding.base64Url().encode(
        BaseEncoding.base64Url().decode(credentialId));
    PublicKeyCredential cred = new PublicKeyCredential(credentialIdRecoded, type,
        BaseEncoding.base64Url().decode(credentialId), assertion);

    Credential savedCredential;
    try {
      savedCredential = Server.validateAndFindCredential(cred, currentUser, session);
    } catch (ResponseException e) {
      throw new ServletException("Unable to validate assertion", e);
    }


    // switch (savedCredential.getCredential().getAttestationType()) {
    // case FIDOU2F:
    // U2fServer.verifyAssertion(cred, currentUser, session, savedCredential);
    // break;
    // case ANDROIDSAFETYNET:
    // AndroidSafetyNetServer.verifyAssertion(cred, currentUser, session, savedCredential);
    // break;
    // case PACKED:
    // PackedServer.verifyAssertion(cred, currentUser, session, savedCredential);
    // break;
    // }

    Server.verifyAssertion(cred, currentUser, session, savedCredential);

    response.setContentType("application/json");
    String handle = DatatypeConverter.printHexBinary(savedCredential.getCredential().rawId);
    
    /*
     * MAKE AN AUTH CODE
     */
    FhirBlocksAuthorizationEngine fba = new FhirBlocksAuthorizationEngine();
    ClientAuthorization ca = new ClientAuthorization();
    
    CsiHandler ch = new CsiHandler();
    CSI csi=null;
    boolean blockChainError=false;
	try {
		Log.info("LOOKING for credential "+credentialIdRecoded);
		//csi = ch.getCSIByUserName(currentUser);  // should be fetched via the credential id used
		LinkedList<CSI> csis = ch.getCSIByAltKey(credentialIdRecoded);
		if (csis.size()==0) {
			Log.info("CSI not found!");
			blockChainError=true;
		}
		if (csis.size()>1) {
			Log.info("too many csi found with same credential id of "+credentialIdRecoded);
			blockChainError=true;
		}
		if (csis.size()==1) {
			csi = csis.get(0);
		}
	} catch (JSONException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (CsiModelException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (KeySpaceException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}

	if (!blockChainError) {
		String audience = "";
		String redirectUri = "https://waa.fhirblocks.io/";
		String state = UUID.randomUUID().toString();
		String scope = "user/patient.read consent.read provenance.read";
		String responseType = "code";
		LinkedList<CSI> orgs;
		String organizationCsiGuid = "org-guid";
		try {
			orgs = ch.getCSIByAltKey("Duke POC Test");
			if (orgs.size()==0) {
				blockChainError=true;
			}
			organizationCsiGuid = orgs.get(0).getClientId();
		} catch (JSONException | CsiModelException | KeySpaceException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
    
    		ca.setAudience(audience);
    		ca.setOrganizationCsiGuid(organizationCsiGuid);
    		ca.setRedirectUri(redirectUri);
    		ca.setResponseType(responseType);
    		ca.setScope(scope);
    		ca.setState(state);
    		ca.setClientId(csi.getClientId());
    	
    		try {
    			ca = fba.createAuthorizationCode(ca);
    		} catch (AuthorizationException ex) {
    			Log.info("error in auth code creation");
    			ex.printStackTrace();
    			blockChainError=true;
		}
	}
    
    String codeToSend = "?code="+ca.getCode();
    codeToSend = URLEncoder.encode(codeToSend, "UTF-8");
    String uri = "";
    if (!blockChainError) {
    		uri = ca.getRedirectUri()+codeToSend;
    } else { // send bad cases to google hehe
    		Log.info("******************* BLOCK CHAIN ERROR ************");
    		uri = "https://s3-us-west-2.amazonaws.com/fhirblocksdocs/warning.html";
    }
    Log.info("redirecting to "+uri);
    PublicKeyCredentialResponse rsp =
        new PublicKeyCredentialResponse(true, "Successful assertion", handle,uri);
    Log.info("FINISH ASSERTION");
    Log.info(rsp.toJson());
    
    response.getWriter().println(rsp.toJson());
    
  }
}
