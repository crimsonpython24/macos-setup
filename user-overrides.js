/******
 * user-overrides.js - arkenfox v140 hardened configuration
 ******/

/*** STARTUP ***/
user_pref("browser.startup.page", 1);
user_pref("browser.startup.homepage", "about:home");
user_pref("browser.newtabpage.enabled", true);

/*** SAFE BROWSING ***/
user_pref("browser.safebrowsing.allowOverride", false);

/*** PROXY ***/
user_pref("network.proxy.failover_direct", false);
user_pref("network.proxy.allow_bypass", false);

/*** LOCATION BAR / SUGGESTIONS ***/
user_pref("browser.urlbar.clipboard.featureGate", false);
user_pref("browser.urlbar.recentsearches.featureGate", false);
user_pref("browser.urlbar.suggest.engines", false);
user_pref("layout.css.visited_links_enabled", false);

/*** PASSWORDS ***/
user_pref("network.http.windows-sso.enabled", false);
user_pref("network.http.microsoft-entra-sso.enabled", false);

/*** HTTPS ***/
user_pref("security.mixed_content.block_display_content", true);
user_pref("dom.security.https_only_mode.upgrade_local", true);

/*** CONTAINERS ***/
user_pref("privacy.userContext.enabled", false);
user_pref("privacy.userContext.ui.enabled", false);

/*** WEBRTC ***/
user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);

/*** FINGERPRINTING VECTORS ***/
user_pref("media.navigator.enabled", false);
user_pref("device.sensors.enabled", false);

/*** MEDIA ***/
user_pref("media.gmp-provider.enabled", false);

/*** MISCELLANEOUS ***/
user_pref("permissions.default.shortcuts", 2);
user_pref("privacy.antitracking.isolateContentScriptResources", true);

/*** ETP ***/
user_pref("privacy.antitracking.enableWebcompat", false);

/*** SHUTDOWN & SANITIZING ***/
user_pref("privacy.clearOnShutdown_v2.cookiesAndStorage", false);
user_pref("privacy.clearOnShutdown_v2.browsingHistoryAndDownloads", true);
user_pref("privacy.clearOnShutdown_v2.downloads", true);
user_pref("privacy.clearOnShutdown_v2.historyFormDataAndDownloads", true);
user_pref("privacy.clearOnShutdown_v2.formdata", true);
user_pref("privacy.clearOnShutdown_v2.cache", true);

/*** FPP ***/
user_pref("privacy.fingerprintingProtection.remoteOverrides.enabled", false);

/*** RFP ***/
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.resistFingerprinting.pbmode", true);
user_pref("privacy.spoof_english", 2);
user_pref("privacy.resistFingerprinting.skipEarlyBlankFirstPaint", true);
user_pref("browser.display.document_color_use", 1);
user_pref("webgl.disabled", true);

/*** OPSEC ***/
user_pref("signon.rememberSignons", false);
user_pref("browser.chrome.site_icons", false);
user_pref("browser.sessionstore.max_tabs_undo", 50);
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.download.forbid_open_with", true);
user_pref("browser.urlbar.suggest.history", false);
user_pref("browser.urlbar.suggest.bookmark", false);
user_pref("browser.urlbar.suggest.openpage", false);
user_pref("browser.urlbar.suggest.topsites", false);
user_pref("browser.urlbar.maxRichResults", 0);
user_pref("browser.urlbar.autoFill", false);
user_pref("browser.taskbar.lists.enabled", false);
user_pref("browser.taskbar.lists.frequent.enabled", false);
user_pref("browser.taskbar.lists.recent.enabled", false);
user_pref("browser.taskbar.lists.tasks.enabled", false);
user_pref("browser.download.folderList", 2);
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.creditCards.enabled", false);
user_pref("dom.popup_allowed_events", "click dblclick mousedown pointerdown");
user_pref("browser.pagethumbnails.capturing_disabled", true);
user_pref("alerts.useSystemBackend.windows.notificationserver.enabled", false);

/*** DOWNLOADS ***/
user_pref("browser.download.always_ask_before_handling_new_types", false);

/*** HARDENING ***/
user_pref("mathml.disabled", true);
user_pref("gfx.font_rendering.graphite.enabled", false);
user_pref("javascript.options.asmjs", false);
user_pref("gfx.font_rendering.opentype_svg.enabled", false);
user_pref("media.eme.enabled", false);
user_pref("browser.eme.ui.enabled", false);

/*** ETP HARDENING ***/
user_pref("privacy.bounceTrackingProtection.mode", 1);
user_pref("network.cookie.cookieBehavior.optInPartitioning", true);

/*** DISABLE FANCY FEATURES ***/
user_pref("extensions.pocket.enabled", false);
user_pref("media.videocontrols.picture-in-picture.enabled", false);
user_pref("media.videocontrols.picture-in-picture.video-toggle.enabled", false);
user_pref("browser.tabs.firefox-view", false);
user_pref("browser.tabs.firefox-view-next", false);
user_pref("browser.tabs.firefox-view-newIcon", false);
user_pref("identity.fxaccounts.enabled", false);
user_pref("sidebar.revamp", false);
user_pref("sidebar.verticalTabs", false);
user_pref("sidebar.main.tools", "");
user_pref("browser.tabs.groups.enabled", false);
user_pref("browser.tabs.hoverPreview.enabled", false);
user_pref("browser.tabs.hoverPreview.showThumbnails", false);
user_pref("browser.tabs.unloadOnLowMemory", false);
user_pref("browser.messaging-system.whatsNewPanel.enabled", false);
user_pref("extensions.screenshots.disabled", true);
user_pref("reader.parse-on-load.enabled", false);
user_pref("browser.translations.enable", false);
user_pref("browser.translations.automaticallyPopup", false);
user_pref("services.sync.engine.tabs", false);
user_pref("extensions.unifiedExtensions.enabled", false);
user_pref("browser.urlbar.quickactions.enabled", false);
user_pref("browser.urlbar.shortcuts.quickactions", false);
user_pref("accessibility.force_disabled", 1);
user_pref("browser.shell.checkDefaultBrowser", false);

/*** DISABLE LEARNING FEATURES ***/
user_pref("browser.urlbar.quicksuggest.enabled", false);
user_pref("browser.urlbar.suggest.quicksuggest.nonsponsored", false);
user_pref("browser.urlbar.suggest.quicksuggest.sponsored", false);
user_pref("browser.urlbar.groupLabels.enabled", false);
user_pref("browser.urlbar.showSearchSuggestionsFirst", false);
user_pref("browser.urlbar.suggest.bestmatch", false);
user_pref("browser.urlbar.suggest.recentsearches", false);
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.urlbar.trending.featureGate", false);
user_pref("browser.formfill.enable", false);
user_pref("browser.urlbar.autoFill.adaptiveHistory.enabled", false);
user_pref("browser.urlbar.contextualSearch.enabled", false);
user_pref("browser.migrate.interactions.bookmarks", false);
user_pref("browser.migrate.interactions.history", false);
user_pref("browser.migrate.interactions.passwords", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("startup.homepage_override_url", "");
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);
user_pref("browser.discovery.enabled", false);
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("browser.urlbar.richSuggestions.featureGate", false);
user_pref("browser.urlbar.searchTips.enabled", false);
user_pref("browser.ping-centre.telemetry", false);
user_pref("toolkit.telemetry.pioneer-new-studies-available", false);

/*** NETWORK HARDENING ***/
user_pref("network.IDN_show_punycode", true);
user_pref("network.dns.disableIPv6", true);
user_pref("network.httpredirection-limit", 5);
user_pref("network.auth.subresource-http-auth-allow", 1);

/*** TLS/CERTIFICATE ***/
user_pref("security.OCSP.require", true);
user_pref("security.cert_pinning.enforcement_level", 2);
user_pref("security.tls.enable_0rtt_data", false);
user_pref("security.ssl.require_safe_negotiation", true);

/*** DOM/JAVASCRIPT ***/
user_pref("dom.disable_window_move_resize", true);
user_pref("dom.event.contextmenu.enabled", false);
user_pref("pdfjs.enableScripting", false);
user_pref("dom.event.clipboardevents.enabled", false);

/*** URL BAR FEATURE GATES ***/
user_pref("browser.urlbar.trimURLs", false);
user_pref("browser.urlbar.addons.featureGate", false);
user_pref("browser.urlbar.weather.featureGate", false);
user_pref("browser.urlbar.yelp.featureGate", false);
user_pref("browser.urlbar.fakespot.featureGate", false);

/*** MISC PRIVACY ***/
user_pref("browser.download.manager.addToRecentDocs", false);
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true);
user_pref("clipboard.autocopy", false);
user_pref("devtools.debugger.force-local", true);
