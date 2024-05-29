export const registerCredential = async() => {
    const opts = {
        attestation: 'none',
        authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            requireResidentKey: false
        }
    };

    const options = await _fetch('/auth/registerRequest', opts);

    options.user.id = base64url.decode(options.user.id);
    options.challenge = base64url.decode(options.challenge);

    if (options.excludeCredentials) {
        for (let cred of options.excludeCredentials) {
            cred.id = base64url.decode(cred.id);
        }
    }

    const cred = await navigator.credentials.create({
        publicKey: options
    });

    const credential = {};
    credential.id = cred.id;
    credential.rawId = base64url.encode(cred.rawId);
    credential.type = cred.type;

    if (cred.response) {
        const clientDataJSON = base64url.encode(cred.response.clientDataJSON);

        const attestationObject = base64url.encode(cred.response.attestationObject);
        credential.response = {
            clientDataJSON,attestationObject
        };
    }

    localStorage.setItem(`credID`, credential.id);

    return await _fetch('/auth/registrationResponse' , credential);
};

export const unregisterCredential = async (credId) => {
    localStorage.removeItem('credId');
    return _fetch(`/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};

