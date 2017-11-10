# -*- coding: utf-8 -*-

import os
import logging
from requests_oauthlib import OAuth2Session
from django.http import HttpResponseRedirect
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.core.urlresolvers import reverse
from django.core.cache import cache
from django.utils.translation import ugettext as _

from seahub import auth
from seahub.profile.models import Profile

import seahub.settings as settings

logger = logging.getLogger(__name__)

if getattr(settings, 'ENABLE_OAUTH_INSECURE_TRANSPORT', False):
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

ENABLE_OAUTH= getattr(settings, 'ENABLE_OAUTH', False)

CLIENT_ID = getattr(settings, 'OAUTH_CLIENT_ID', '')
CLIENT_SECRET = getattr(settings, 'OAUTH_CLIENT_SECRET', '')
AUTHORIZATION_URL = getattr(settings, 'OAUTH_AUTHORIZATION_URL', '')
REDIRECT_URL = getattr(settings, 'OAUTH_REDIRECT_URL', '')
TOKEN_URL = getattr(settings, 'OAUTH_TOKEN_URL', '')
USER_INFO_URL = getattr(settings, 'OAUTH_USER_INFO_URL', '')
SCOPE = getattr(settings, 'OAUTH_SCOPE', [])

if ENABLE_OAUTH and (not CLIENT_ID or not CLIENT_SECRET or \
        not AUTHORIZATION_URL or not REDIRECT_URL or \
        not TOKEN_URL or not USER_INFO_URL):

    logger.info('CLIENT_ID: %s' % CLIENT_ID)
    logger.info('CLIENT_SECRET: %s' % CLIENT_SECRET)
    logger.info('AUTHORIZATION_URL: %s' % AUTHORIZATION_URL)
    logger.info('REDIRECT_URL: %s' % REDIRECT_URL)
    logger.info('TOKEN_URL: %s' % TOKEN_URL)
    logger.info('USER_INFO_URL: %s' % USER_INFO_URL)
    logger.info('SCOPE: %s' % SCOPE)


class Oauth2(object):

    def __init__(self):
        self.session = OAuth2Session(client_id=CLIENT_ID,
                scope=SCOPE, redirect_uri=REDIRECT_URL)

    def get_authorization_url_and_state(self):
        authorization_url, state = self.session.authorization_url(
                AUTHORIZATION_URL)

        return authorization_url, state

    def get_access_token(self, state, authorization_response):
        self.session.fetch_token(
                TOKEN_URL, client_secret=CLIENT_SECRET,
                authorization_response=authorization_response)

    def get_user_info(self):

        user_info = {
            'email': '',
            'name': '',
            'contact_email': '',
        }

        user_info_response = self.session.get(USER_INFO_URL)
        email = user_info_response.json().get('email')
        name = user_info_response.json().get('name')

        user_info['email'] = email
        user_info['name'] = name
        user_info['contact_email'] = email

        return user_info

oauth = Oauth2()

def oauth_login(request):
    """Step 1: User Authorization.
    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """

    if not ENABLE_OAUTH:
        return render_to_response('error.html', {
                'error_msg': _('Please enable oauth first.'),
                }, context_instance=RequestContext(request))

    try:
        authorization_url, state = oauth.get_authorization_url_and_state()
    except Exception as e:
        logger.error(e)
        return render_to_response('error.html', {
                'error_msg': _('Internal Server Error'),
                }, context_instance=RequestContext(request))

    cache_key = 'oauth_state_cache_key'
    cache.set(cache_key, state, 24 * 60 * 60)

    return HttpResponseRedirect(authorization_url)

# Step 2: User authorization, this happens on the provider.
def oauth_callback(request):
    """ Step 3: Retrieving an access token.
    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """

    if not ENABLE_OAUTH:
        return render_to_response('error.html', {
                'error_msg': _('Please enable oauth first.'),
                }, context_instance=RequestContext(request))

    cache_key = 'oauth_state_cache_key'
    state = cache.get(cache_key)

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    try:
        oauth.get_access_token(state, request.get_full_path())
        user_info = oauth.get_user_info()
    except Exception as e:
        logger.error(e)
        return render_to_response('error.html', {
                'error_msg': _('Internal Server Error'),
                }, context_instance=RequestContext(request))


    # seahub authenticate user
    email = user_info['email']
    name = user_info['name']
    contact_email = user_info['contact_email']
    user = auth.authenticate(remote_user=email)

    if not user or not user.is_active:
        # a page for authenticate user failed
        return HttpResponseRedirect(reverse('libraries'))

    # User is valid.  Set request.user and persist user in the session
    # by logging the user in.
    request.user = user
    auth.login(request, user)
    user.set_unusable_password()
    user.save()

    # update user's profile
    profile = Profile.objects.get_profile_by_user(email)
    if not profile:
        profile = Profile(user=email)

    if name.strip():
        profile.nickname = name

    if contact_email.strip():
        profile.contact_email = contact_email

    profile.save()

    # redirect user to home page
    return HttpResponseRedirect(reverse('libraries'))
