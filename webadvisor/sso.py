#!/usr/bin/python
# -*- coding: UTF-8 -*-

# WebAdvisor Python API
# Author: Steven L. Smith, Web Developer, Nazareth College
# Last Modified: 2011-03-02

# WebAdvisor Settings
# Change these values to reflect your WebAdvisor setup
WEBADVISOR_SSO_URL_TEST = 'http://naznet2.naz.edu/nazdev/SingleSignOn'
WEBADVISOR_SSO_URL_PROD = 'https://naznet.naz.edu/naznet/SingleSignOn'
LIVE = True	# True = Use the PROD URL, False = Use the TEST URL

##
# You shouldn't need to change anything below this line
##

# This software has been released under the BSD 3-Clause License.
#
# Copyright (c) 2011, Nazareth College of Rochester
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#   * Neither the name of Nazareth Collge nor the names of its contributors may
#     be used to endorse or promote products derived from this software without
#     specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


# Try and get ElementTree from someplace...
try:
	import lxml.etree as ET
except ImportError:
	try:
		import xml.etree.ElementTree as ET
	except ImportError:
		import elementtree.ElementTree as ET

# Other needed imports
from httplib import HTTPConnection, HTTPSConnection, UnknownProtocol
import cgi

# In order, based on the "result" attributes of the "LogOn" element
LOGON_RESULTS = (
	"Successful login",
	"Password has expired",
	"Invalid username or password",
	"Invalid account",
)

# Get the correct URL, based on what mode we're in (see settings above)
if LIVE:
	WEBADVISOR_SSO_URL = WEBADVISOR_SSO_URL_PROD
else:
	WEBADVISOR_SSO_URL = WEBADVISOR_SSO_URL_TEST



# These are helper functions used by the core API.
# You probably won't need to use these directly.
def format_xml(xml):
	"""Append XML version and DOCTYPE declarations to XML string."""
	return '<?xml version="1.0"?><!DOCTYPE Request SYSTEM "SSORequest.dtd">' + ET.tostring(xml)


def send_xml(xml):
	"""Send an XML document to WebAdvisor and return result XML string."""
	protocol, junk, server, path = WEBADVISOR_SSO_URL.split('/', 3)
	if protocol == 'https:':
		conn = HTTPSConnection(server)
	elif protocol == 'http:':
		conn = HTTPConnection(server)
	else:
		raise UnknownProtocol

	conn.request("POST", '/' + path, xml, {'Content-Type': 'text/xml',})
	resp = conn.getresponse()
	return resp.read()



# These are the 4 actual API functions you may use in your integration.
# Documentation may be found in each function's docstring.
def login(username, password, account=None):
	"""Log a user in and return dict containing status code and token.
	If unsucessful, the value of token will be None.

	Arguments:
	username -- WebAdvisor username (string)
	password -- WebAdvisor password (string)

	Keyword arguments:
	account -- the colleague account to log into (default None)

	"""
	req = ET.Element("Request")
	logon = ET.SubElement(req, "LogOn")
	logon.set("username", username)
	logon.set("password", password)
	if account:
		logon.set("account", account)
	xml = format_xml(req)
	returned_xml = send_xml(xml)

	tree = ET.fromstring(returned_xml)
	code = tree[0].attrib.get('result')
	text = cgi.escape(returned_xml)
	if code:
		code = int(code)
		text = LOGON_RESULTS[code]
	token = tree[0].attrib.get('token')
	return {
		'status_code': code,
		'status_text': text,
		'token': token,
	}


def is_logged_in(token):
	"""Check if user (token) is logged in or not. Returns Boolean."""
	req = ET.Element("Request")
	LoggedOn = ET.SubElement(req, "LoggedOn")
	LoggedOn.set("token", token)
	xml = format_xml(req)
	returned_xml = send_xml(xml)
	tree = ET.fromstring(returned_xml)
	return tree[0].attrib.get('result') == 'true'


def logout(token):
	"""Log a user (token) out, and return True if successful."""
	req = ET.Element("Request")
	LogOff = ET.SubElement(req, "LogOff")
	LogOff.set("token", token)
	xml = format_xml(req)
	returned_xml = send_xml(xml)
	tree = ET.fromstring(returned_xml)
	return tree[0].attrib.get('result') == 'true'


def change_password(username, old_password, new_password):
	"""Change a password.

	Arguments:
	username -- WebAdvisor username
	old_password -- Old / Current password
	new_password -- New password

	The new password must meet WebAdvisor password complexity requirements.
	You may wish to validate that the password meets requirements before
	invoking this function. Since False is returned if the password reset
	is unsuccessful for *any* reason, it is not possible to tell *why*
	the password reset failed.

	"""
	req = ET.Element("Request")
	changepw = ET.SubElement(req, "ChangePassword")
	changepw.set("username", username)
	changepw.set("password", old_password)
	changepw.set("newpassword", new_password)
	xml = format_xml(req)
	returned_xml = send_xml(xml)
	tree = ET.fromstring(returned_xml)
	return tree[0].attrib.get('result') == 'true'
