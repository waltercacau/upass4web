/*
    upass4web - Unix Pass Utility for the Web
    Copyright (C) 2012 Walter Cacau

    upass4web is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    upass4web is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with upass4web.  If not, see <http://www.gnu.org/licenses/>.
*/

var upass4web = {};
(function() {
    upass4web.errors = {
        "Error": Error
    };
    function BaseError(message) {
        Error.call(this);
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
        this.name = this.constructor.name;
        this.message = message || '';
    }

    function create_error(name, super_) {
        if(!super_) {
            super_ = "Error";
        }
        /*jshint evil:true */
        var code =
            "function " + name + "() {\n" +
            "    BaseError.apply(this, arguments);\n" +
            "};\n" +
            name + ".prototype.__proto__ = upass4web.errors." + super_ + ".prototype;\n" +
            name + ".prototype.toString = function() {\n" +
            "    if ( this.message )\n" +
            "        return this.name + ': ' + this.message;\n" +
            "    else\n" +
            "        return this.name;\n" +
            "};\n" +
            name;
        upass4web.errors[name] = eval(code);
    }
    create_error("PasswordNotFoundError");
    create_error("KeyNotFoundError");
    create_error("ParsingTextError");
    create_error("NoKeyInArmoredTextError", "ParsingTextError");
    create_error("MoreThenOneKeyInArmoredTextError", "ParsingTextError");
    create_error("NoMessageInTextError", "ParsingTextError");
    create_error("MoreThenOneMessageInTextError", "ParsingTextError");
})();

upass4web.log = {};
upass4web.log.error = Function.prototype.bind.apply(console.error, [console]);
upass4web.log.warn = Function.prototype.bind.apply(console.warn, [console]);
upass4web.log.info = Function.prototype.bind.apply(console.info, [console]);


upass4web.PasswordStore = function() {
    this.passwords = null;
};
upass4web.PasswordStore.prototype.LOCAL_STORAGE_KEY = "upass4web-passwords";
upass4web.PasswordStore.prototype.load = function() {
    var rawPasswords = JSON.parse(
        window.localStorage.getItem(
            this.LOCAL_STORAGE_KEY
        ) || "[]"
    );
    this.passwords = {};
    for(var i=0, len=rawPasswords.length; i < len; i++) {
        try {
            this.put(rawPasswords[i].name, rawPasswords[i].content);
        } catch(err) {
            upass4web.log.error("Skipping password " + rawPasswords[i].name);
        }
    }
};

upass4web.PasswordStore.prototype.put = function(name, content) {
    var result = openpgp.read_messages_dearmored(
        {openpgp: content, type: 3}
    );
    if (result.length > 1) {
        throw new upass4web.errors.MoreThenOneMessageInTextError();
    } else if (result.length === 0) {
        throw new upass4web.errors.NoMessageInTextError();
    }
    this.passwords[name] = {
        name: name,
        obj: result[0],
        content: content
    };
};

upass4web.PasswordStore.prototype.remove = function(name) {
    if (!this.passwords[name]) {
        throw new upass4web.errors.PasswordNotFoundError(name);
    }
    delete this.passwords[name];
};

upass4web.PasswordStore.prototype.rename = function(src, dest) {
    if (!this.passwords[src]) {
        throw new upass4web.errors.PasswordNotFoundError(src);
    }
    if(dest != src) {
        this.passwords[dest] = this.passwords[src];
        delete this.passwords[src];
    }
};

upass4web.PasswordStore.prototype.save = function() {
    var rawPasswords = [];

    for(var name in this.passwords) {
        rawPasswords.push({
            name: name,
            content: this.passwords[name].content
        });
    }

    window.localStorage.setItem(
        this.LOCAL_STORAGE_KEY,
        JSON.stringify(rawPasswords)
    );
};

upass4web.KeyStore = function() {
    this.keys = null;
};
upass4web.KeyStore.prototype.LOCAL_STORAGE_KEY = "upass4web-keys";
upass4web.KeyStore.prototype.load = function() {
    var rawKeys = JSON.parse(
        window.localStorage.getItem(
            this.LOCAL_STORAGE_KEY
        ) || "[]"
    );
    this.keys = {};
    for(var i=0, len=rawKeys.length; i < len; i++) {
        this.put(rawKeys[i]);
    }
};
upass4web.KeyStore.prototype.save = function() {
    var rawKeys = [];

    for(var name in this.keys) {
        rawKeys.push(this.keys[name].armored);
    }

    window.localStorage.setItem(
        this.LOCAL_STORAGE_KEY,
        JSON.stringify(rawKeys)
    );
};
upass4web.KeyStore.prototype.put = function(armoredText) {
    var result = openpgp.read_privateKey(armoredText);
    if (result.length > 1) {
        throw new upass4web.errors.MoreThenOneKeyInArmoredTextError();
    } else if (result.length === 0) {
        throw new upass4web.errors.NoKeyInArmoredTextError();
    }
    var key = {
        armored: armoredText,
        obj: result[0]
    };
    this.keys[result[0].getKeyId()] = key;
    return key;
};

upass4web.KeyStore.prototype.remove = function(keyId) {
    if (!this.keys[keyId]) {
        throw new upass4web.errors.KeyNotFoundError(keyId);
    }
    delete this.keys[keyId];
};


upass4web.getUserForKey = function(key) {
    return key.obj.userIds[0] ? key.obj.userIds[0].text : "";
};

upass4web.getPrettyIdForKey = function(key) {
    return "0x" + openpgp._upass4web.util.hexstrdump(
        key.obj.getKeyId()
    ).substring(8);
};
upass4web.getOrigin = function(location) {
    location = location || window.location;
    return location.protocol + "//" + location.host;
};

upass4web.KeyStore.prototype.getKeyForDecryption = function(keyId) {
    if (keyId in this.keys) {
        return {
            key: this.keys[keyId],
            keymaterial: this.keys[keyId].obj.keymaterial
        };
    }
    for (var id in this.keys) {
        var key = this.keys[id];
        if (key.obj.subKeys === null) {
            continue;
        }
        var subkeyids = key.obj.getSubKeyIds();
        for (var j=0; j < subkeyids.length; j++) {
            if (keyId == openpgp._upass4web.util.hexstrdump(subkeyids[j])) {
                return {
                    key: key,
                    keymaterial: key.obj.subKeys[j]
                };
            }
        }
    }
};

upass4web.KeyViewModel = function(key) {
    this.key = key;
    this.id = upass4web.getPrettyIdForKey(key);
    this.user = upass4web.getUserForKey(key);
    if ( this.user ) {
        this.displayName = this.user + " (" + this.id + ")";
    } else {
        this.displayName = this.id;
    }
};

upass4web.PasswordViewModel = function(password) {
    this.password = password;
    this.displayName = this.password.name;
};

upass4web.compareDisplayName = function(a, b) {
    if (a.displayName < b.displayName)
        return -1;
    if (a.displayName > b.displayName)
        return 1;
    return 0;
};

upass4web.AppViewModel = function() {
    this.keyStore = new upass4web.KeyStore();
    this.keyStore.load();
    this.keys = ko.observableArray();
    this.rebuildKeyList();

    this.passwordStore = new upass4web.PasswordStore();
    this.passwordStore.load();
    this.passwords = ko.observableArray();
    this.rebuildPasswordList();

    this.bookmarkletLink = upass4web.bookmarklet.getLink();

    // For the UI trick with file inputs
    this.uploadKeyFilePath = ko.observable();
    this.uploadPasswordFilePath = ko.observable();

};

upass4web.AppViewModel.prototype.rebuildKeyList = function() {
    this.keys.splice(0, this.keys().length);
    for(var id in this.keyStore.keys) {
        this.keys.push(
            new upass4web.KeyViewModel(
                this.keyStore.keys[id]
            )
        );
    }
    this.keys.sort(upass4web.compareDisplayName);
};

upass4web.AppViewModel.prototype.rebuildPasswordList = function() {
    this.passwords.splice(0, this.passwords().length);
    for(var id in this.passwordStore.passwords) {
        this.passwords.push(
            new upass4web.PasswordViewModel(
                this.passwordStore.passwords[id]
            )
        );
    }
    this.passwords.sort(upass4web.compareDisplayName);
};

upass4web.AppViewModel.prototype.getTextFile = function(selector) {
    var deferred = $.Deferred();
    var file = $(selector)[0].files[0];
    if(!file) {
        alert("Select a file first!");
        deferred.reject();
        return deferred;
    }
    if(file.size > 1024*1024) {
        alert("File is too big (1 MB max)");
        deferred.reject();
        return deferred;
    }
    var reader = new FileReader();
    reader.onload = function() {
        deferred.resolve(file, reader.result);
    };
    reader.readAsBinaryString(file);
    return deferred;
};

upass4web.AppViewModel.prototype.uploadKey = function() {
    this.getTextFile("#uploadKeyFile").then(function(file, armoredText) {
        try {
            this.keyStore.put(armoredText);
        } catch(err) {
            upass4web.log.error(err);
            alert("Could not open key file");
            return;
        }
        this.keyStore.save();
        this.rebuildKeyList();
    }.bind(this));
};

upass4web.AppViewModel.prototype.uploadPassword = function() {
    this.getTextFile("#uploadPasswordFile").then(function(file, content) {
        var name = file.name;
        var extIndex = name.indexOf(".gpg");
        if(extIndex != -1) {
            name = name.substring(0, extIndex);
        }
        try {
            this.passwordStore.put(name, content);
        } catch(err) {
            upass4web.log.error(err);
            alert("Could not open password file");
            return;
        }
        this.passwordStore.save();
        this.rebuildPasswordList();
    }.bind(this));
};

upass4web.AppViewModel.prototype.removePassword = function(passwordModel) {
    if(confirm(
        "Are you sure you want to remove password " +
        passwordModel.displayName + "?"
    )) {
        this.passwordStore.remove(passwordModel.password.name);
        this.passwordStore.save();
        this.rebuildPasswordList();
    }
};

upass4web.AppViewModel.prototype.viewPassword = function(passwordModel) {
    upass4web.decryptPassword(passwordModel.password, this.keyStore).then(
        function(password) {
            alert(password);
        }
    );
};

upass4web.AppViewModel.prototype.removeKey = function(keyModel) {
    if(confirm(
        "Are you sure you want to remove password " +
        keyModel.displayName + "?"
    )) {
        this.keyStore.remove(keyModel.key.obj.getKeyId());
        this.keyStore.save();
        this.rebuildKeyList();
    }
};

upass4web.decryptPassword = function(password, keyStore) {
    var deferred = $.Deferred();
    var sessionKeys = password.obj.sessionKeys;
    var sessionKey;
    var keyForDecryption;
    var i;
    for(i = 0, len = sessionKeys.length; i < len; i++) {
        keyForDecryption = keyStore.getKeyForDecryption(
            sessionKeys[i].keyId
        );
        if (keyForDecryption) {
            sessionKey = sessionKeys[i];
            break;
        }
    }
    if ( !keyForDecryption ) {
        alert("Could not find key for password " + password.name);
        deferred.reject();
        return deferred;
    }

    var key = keyForDecryption.key;
    var keymaterial = keyForDecryption.keymaterial;

    function finish() {
        if (!keymaterial.secMPIs) {
            deferred.reject();
            return deferred;
        }
        deferred.resolve(password.obj.decrypt(keyForDecryption, sessionKey));
        return deferred;
    }
    var attempts = 0;
    function tryGettingPasswordForDecrypting() {
        if (keymaterial.secMPIs) {
            return finish();
        }
        return upass4web.popup.getPassword(
            (attempts > 0 ? "Wrong password, try again.\n" : "") +
            "Password for key " + upass4web.getUserForKey(key)
        ).then(function(passwordForKey) {
            if (keymaterial.decryptSecretMPIs(passwordForKey)) {
                return finish();
            }
            attempts += 1;
            if (attempts < 3) {
                return tryGettingPasswordForDecrypting();
            } else {
                alert("Giving after " + attempts +  " attempts");
                deferred.reject();
                return deferred;
            }
        });
    }

    return tryGettingPasswordForDecrypting();

};

upass4web.initWebapp = function() {

    $(document).ready(function() {
        if (location.hash !== '') $('a[href="' + location.hash + '"]').tab('show');
        return $('a[data-toggle="tab"]').on('shown', function(e) {
          return location.hash = $(e.target).attr('href').substr(1);
        });
    });

    openpgp.init();
    upass4web.appViewModel = new upass4web.AppViewModel();
    ko.applyBindings(upass4web.appViewModel);

};

upass4web.initEmbed = function() {
    openpgp.init();
    var keyStore = new upass4web.KeyStore();
    var passwordStore = new upass4web.PasswordStore();
    var bookmarkletHash = upass4web.bookmarklet.getHash();
    keyStore.load();
    passwordStore.load();

    function parseUrl( url ) {
        var a = document.createElement('a');
        a.href = url;
        return a;
    }
    window.addEventListener("message", function(event) {
        if (!event.origin)
            return;
        if (
            !event.data ||
            event.data.sourceScript != "upass4webBookmarklet"
        ) {
            return;
        }
        if (!event.data.hash || event.data.hash != bookmarkletHash) {
            if(confirm(
                "Bookmarklet is outdated. Please, reinstall it.\n" +
                "I will redirect you to upass4web page so you can " +
                "reinstall, ok?"
            )) {
                window.top.focus();
                window.top.location = upass4web.getOrigin(window.location) +
                                      "/upass4web.html";
            }
            return;
        }

        var hostname = parseUrl(event.origin).hostname;

        if (! (hostname in passwordStore.passwords)) {
            alert("Could not find a password named " + hostname);
            return;
        }

        upass4web.decryptPassword(
            passwordStore.passwords[hostname],
            keyStore
        ).then(function(password) {
            var cutIndex = password.indexOf("\n");
            if (cutIndex == -1) {
                cutIndex = password.indexOf("\r");
            }
            if (cutIndex != -1) {
                password = password.substring(0, cutIndex);
            }
            event.source.postMessage(
                {
                    sourceScript: "upass4web",
                    password: password
                },
                event.origin
            );
        }).always(function() {
            popupWin.close();
        });

    }, false);
};

upass4web.bookmarklet = {};
upass4web.bookmarklet._generate = function() {
    var func = JSON.stringify(
        "(" + upass4web.bookmarklet.template.toString() + ")"
    );
    var origin = JSON.stringify(upass4web.getOrigin(window.location));
    var code = "eval(" + func + ")(" + origin +
               ", '/upass4webEmbed.html', $HASH$)";
    var hash = openpgp._upass4web.util.hexstrdump(
        openpgp._upass4web.str_sha1(code)
    );
    return {
        code: code.replace("$HASH$", JSON.stringify(hash)),
        hash: hash
    };
};

upass4web.bookmarklet.getHash = function() {
    return upass4web.bookmarklet._generate().hash;
};

upass4web.bookmarklet.getLink = function() {
    return "javascript:" + encodeURIComponent(
        upass4web.bookmarklet._generate().code
    );
};

upass4web.bookmarklet.template = function(origin, path, hash) {
    if(window.upass4webBookmarklet) {
        window.upass4webBookmarklet.uninstall();
    }
    var upass4webBookmarklet = window.upass4webBookmarklet = {};

    upass4webBookmarklet.iframe = document.createElement("iframe");
    upass4webBookmarklet.iframe.style.display = "none";
    document.body.appendChild(upass4webBookmarklet.iframe);

    upass4webBookmarklet._processMessage = function(event) {
        if (
            event.origin != origin ||
            !event.data ||
            event.data.sourceScript !== "upass4web"
        ) {
            return;
        }
        upass4webBookmarklet.input.value = event.data.password;
        upass4webBookmarklet.input.focus();
        upass4webBookmarklet.input = null;
    };

    window.addEventListener(
        "message", upass4webBookmarklet._processMessage, false
    );

    upass4webBookmarklet.uninstall = function() {
        upass4webBookmarklet.iframe.contentWindow.location = "about:blank";
        upass4webBookmarklet.iframe.parentNode.removeChild(
            upass4webBookmarklet.iframe
        );
        window.removeEventListener(
            "message", upass4webBookmarklet._processMessage, false
        );
        delete window.upass4webBookmarklet;
    };

    upass4webBookmarklet._isHidden = function( elem ) {
        var width = elem.offsetWidth,
            height = elem.offsetHeight;

        return ( width === 0 && height === 0 ) ||
               ( (elem.style && elem.style.display) ||
                  elem.style.display) === "none";
    };

    upass4webBookmarklet._discoverInput = function() {
        var active = document.activeElement;
        if (active && active.type == "password") {
            return active;
        }
        var inputs = Array.prototype.slice.apply(
            document.querySelectorAll('input[type=password]')
        );
        for(var i = 0; i < inputs.length; i++) {
            if(!upass4webBookmarklet._isHidden(inputs[i]) && inputs[i].type === "password") {
                return inputs[i];
            }
        }
    };

    upass4webBookmarklet.getPassword = function() {
        upass4webBookmarklet.input = upass4webBookmarklet._discoverInput();
        if(!upass4webBookmarklet.input) {
            alert("Could not find password input");
            return;
        }
        upass4webBookmarklet.iframe.onload = function() {
            upass4webBookmarklet.iframe.contentWindow.postMessage(
                {
                    sourceScript: "upass4webBookmarklet",
                    hash: hash
                },
                origin
            );
        };
        upass4webBookmarklet.iframe.src = origin + path;
    };

    upass4webBookmarklet.getPassword();
};

upass4web.popup = {};
upass4web.popup._current = null;
upass4web.popup._popupCallback = function(popupWin) {
    if (upass4web.popup._current.window !== popupWin) {
        popupWin.close();
    } else {
        popupWin.onbeforeunload = function() {
            if (upass4web.popup._current) {
                upass4web.popup._current.onclose(popupWin);
                upass4web.popup._current = null;
            }
        };
        upass4web.popup._current.onready(popupWin);
    }
};

upass4web.popup.preopen = function(origin) {
    var windowWidth = 300;
    var windowHeight = 200;

    var centerWidth = (window.screen.width - windowWidth) / 2;
    var centerHeight = (window.screen.height - windowHeight) / 2;

    var popupWin = window.open(
        origin ? origin + '/upass4webPopup.html' : '', 'upass4webPopup', (
            'menubar=no,status=no,toolbar=no,width=' + windowWidth +
            ',height=' + windowHeight +
            ',left=' + centerWidth +
            ',top=' + centerHeight
        )
    );

    return popupWin;
};

upass4web.popup._popupOpen = function(onready, onclose) {
    if (upass4web.popup._current) {
        upass4web.popup._current.window.close();
    }
    var popupWin = upass4web.popup.preopen();
    upass4web.popup._current = {
        window: popupWin,
        onready: onready || function() {},
        onclose: onclose || function() {}
    };

    var isready = false;
    try {
        isready = popupWin.upass4webReady;
    } catch(err) {}

    if (isready) {
        upass4web.popup._popupCallback(popupWin);
    } else {
        popupWin.location = "upass4webPopup.html";
    }
    // TODO: add timeout and fire onclose automatically
};

upass4web.popup.getPassword = function(message) {
    var deferred = $.Deferred();
    var done = false;
    upass4web.popup._popupOpen(
        function(popupWin) {
            popupWin.$("#passwordPopup .message").html(
                $("<div>").text(message).html().replace("\n", "<br />")
            );
            popupWin.$("#passwordPopup form").submit(function(event) {
                event.preventDefault();
                done = true;
                popupWin.close();
                deferred.resolve(popupWin.$("#passwordPopup input").val());
            });
            popupWin.$("#passwordPopup .btn-danger").click(function() {
                popupWin.close();
            });
            popupWin.$("#passwordPopup input").focus();
        },
        function() {
            if (!done) {
                done = true;
                deferred.reject();
            }
        }
    );
    return deferred;
};
