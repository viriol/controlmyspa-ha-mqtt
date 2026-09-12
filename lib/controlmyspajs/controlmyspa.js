const querystring = require('querystring');
const dns = require('dns');
const https = require('https');
const axios = require('axios').default;

const logDebug = require('debug')('spa:debug');
const logError = require('debug')('spa:error');
const logInfo = require('debug')('spa:info');

// ---------------------------------------------------------------------------
// DNS cache + fallback
//
// Balboas/ControlMySpas namnservrar (ns29/ns30.worldnic.com) har visat sig
// vara intermittent trasiga ("lame delegation" / SERVFAIL). Ett vanligt
// axios/Node-anrop gör en helt färsk DNS-uppslagning för varje enskild
// request och har ingen egen cache, så det är extremt känsligt för detta.
//
// Den här funktionen sparar senast lyckade uppslagning per hostname. Om en
// färsk uppslagning misslyckas, används det senast kända fungerande svaret
// istället för att låta hela anropet krascha med getaddrinfo/EAI_AGAIN.
// ---------------------------------------------------------------------------
const dnsCache = new Map(); // hostname -> { address, family, timestamp }

// Startvärde: senast kända, stabila IP för iot.controlmyspa.com (oförändrad
// under hela vår felsökning över flera månader). Detta gör att fallbacken
// fungerar redan vid allra första försöket efter en omstart, utan att
// behöva vänta på att HA:s egen DNS-uppslagning lyckas minst en gång -
// vilket visat sig vara opålitligt oberoende av vad vi gör (se ha dns
// options/restart-felsökningen). Skrivs över automatiskt av en riktig,
// färsk uppslagning så fort en sådan lyckas.
dnsCache.set('iot.controlmyspa.com', {
  address: '13.83.102.3',
  family: 4,
  timestamp: Date.now() // startvärde satt vid modulens laddning, skrivs över av första lyckade uppslagning
});

function cachedLookup (hostname, options, callback) {
  // dns.lookup kan anropas som (hostname, callback) eller (hostname, options, callback)
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  dns.lookup(hostname, options, (err, address, family) => {
    if (!err) {
      dnsCache.set(hostname, { address, family, timestamp: Date.now() });
      return callback(null, address, family);
    }

    logError(`DNS lookup failed for ${hostname}: ${err.message}`);

    // Ingen åldersgräns - så länge vi någonsin lyckats slå upp hostname,
    // används senast kända fungerande IP tills en färsk uppslagning lyckas
    // och skriver över den. Skrivs över automatiskt vid varje lyckat försök.
    const cached = dnsCache.get(hostname);
    if (cached) {
      const ageSeconds = Math.round((Date.now() - cached.timestamp) / 1000);
      logDebug(`Using cached DNS result for ${hostname}: ${cached.address} (cached ${ageSeconds}s ago)`);
      return callback(null, cached.address, cached.family);
    }

    return callback(err);
  });
}

const httpsAgent = new https.Agent({
  lookup: cachedLookup,
  keepAlive: true
});

// Delad axios-instans som alla anrop i den här filen använder, så att
// DNS-cachen/fallbacken gäller överallt utan att varje enskilt anrop
// behöver ange httpsAgent manuellt.
const client = axios.create({ httpsAgent });

class ControlMySpa {
  constructor (email, password, celsius = true) {
    this.celsius = celsius;
    this.email = email;
    this.password = password;

    // Access token data
    this.tokenData = null;

    // WhoAMI / Owner
    this.userInfo = null;

    // Spa setup
    this.currentSpa = null;
    this.currentSpaId = null;

    this.waitForResult = false;

    this.scheduleFilterIntervalEnum = null;
  }

  async init () {
    return (
      (await this.login()) &&
      (await this.getProfile()) &&
      (await this.getDefaultSpa()) &&
      (await this.getSpa())
    );
  }

  async login () {
    logDebug('Logging in via /auth/login');

    const req = await client.post(
      'https://iot.controlmyspa.com/auth/login',
      {
        email: this.email,
        password: this.password
      },
      {
        headers: {
          Accept: 'application/json, text/plain, */*',
          'Content-Type': 'application/json'
        }
      }
    );

    if (req.status === 200) {
      const body = req.data.data;
      this.tokenData = body;

      logDebug('Login ok, token received');
      return true;
    } else {
      throw new Error('Failed to login: ' + req.status);
    }
  }

  // Förnyar access token via Azure B2C:s OAuth2-token-endpoint direkt, med hjälp
  // av refresh_token vi redan fått från /auth/login. Kräver inget lösenord och
  // belastar inte Balboas egen (historiskt sköra) inloggnings-endpoint.
  //
  // VIKTIGT: Azure B2C roterar refresh_token vid varje användning - den gamla
  // blir ogiltig så fort en ny hämtats. Vi MÅSTE alltså spara den nya
  // refresh_token som kommer i svaret, inte återanvända den gamla.
  //
  // client_id nedan är samma "azp"-värde vi hittade i den dekodade access-
  // token-JWT:n. Om Balboa någon gång byter denna, kommer anropet ge ett
  // tydligt AADB2C-felmeddelande (Azure B2C är ovanligt bra på beskrivande
  // fel), vilket gör den betydligt lättare att felsöka än de tysta 404:orna
  // vi vant oss vid.
  async refreshAccessToken () {
    logDebug('Refreshing access token via Azure B2C token endpoint');

    if (!this.tokenData || !this.tokenData.refreshToken) {
      throw new Error('No refresh token available to refresh with');
    }

    const params = new URLSearchParams();
    params.append('grant_type', 'refresh_token');
    params.append('client_id', '7a7f262e-4370-479a-ba35-ffe8abae7509');
    params.append('refresh_token', this.tokenData.refreshToken);

    const req = await client.post(
      'https://iamqacontrolmyspa.b2clogin.com/bbe31193-4476-47dd-82c4-c993f641c830/B2C_1_CMS_USER_PWD/oauth2/v2.0/token',
      params.toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    if (req.status === 200) {
      // OBS: svarets fältnamn (access_token/refresh_token/expires_in) är
      // snake_case (rå Azure B2C-standard), till skillnad från /auth/login
      // som ger camelCase (accessToken/refreshToken). Vi normaliserar här
      // till samma camelCase-struktur som resten av koden förväntar sig.
      this.tokenData = {
        accessToken: req.data.access_token,
        refreshToken: req.data.refresh_token,
        expiresIn: req.data.expires_in
      };

      logDebug(`Access token refreshed, expires in ${req.data.expires_in}s`);
      return true;
    } else {
      throw new Error('Failed to refresh access token: ' + req.status);
    }
  }

  // Primär: /user-agreements/current (originalintegrationens ändpunkt)
  // Fallback: /web/user-management/profile (den vi hittade via webb-sniffning)
  async getProfile () {
    logDebug('Requesting profile data');

    try {
      const req = await client.get(
        'https://iot.controlmyspa.com/user-agreements/current', {
        headers: {
          Accept: '*/*',
          Authorization: 'Bearer ' + this.tokenData.accessToken
        }
      });
      this.userInfo = req.data.data.agreement.userId;
      logDebug(`User profile found ${JSON.stringify(this.userInfo)}`);
      return this.userInfo;
    } catch (err) {
      logError(`Primary endpoint (user-agreements/current) failed: ${err.message}. Trying fallback (web/user-management/profile)...`);

      const fallbackReq = await client.get(
        'https://iot.controlmyspa.com/web/user-management/profile', {
        headers: {
          Accept: '*/*',
          Authorization: 'Bearer ' + this.tokenData.accessToken
        }
      });
      this.userInfo = fallbackReq.data.data.user._id;
      logDebug(`User profile found via fallback ${JSON.stringify(this.userInfo)}`);
      return this.userInfo;
    }
  }

  // Primär: /spas/owned (originalintegrationens ändpunkt)
  // Fallback: /web/spas?page=0&pageSize=20
  async getDefaultSpa () {
    logDebug('Requesting default spa data');

    try {
      const req = await client.get(
        'https://iot.controlmyspa.com/spas/owned',
        {
          headers: {
            Accept: '*/*',
            Authorization: 'Bearer ' + this.tokenData.accessToken
          }
        }
      );
      this.currentSpaId = req.data.data.spas[0]._id;
      logDebug('Default spa id: ' + this.currentSpaId);
      return this.currentSpaId;
    } catch (err) {
      logError(`Primary endpoint (spas/owned) failed: ${err.message}. Trying fallback (web/spas)...`);

      const fallbackReq = await client.get(
        'https://iot.controlmyspa.com/web/spas?page=0&pageSize=20',
        {
          headers: {
            Accept: '*/*',
            Authorization: 'Bearer ' + this.tokenData.accessToken
          }
        }
      );
      this.currentSpaId = fallbackReq.data.data.spas[0]._id;
      logDebug('Default spa id via fallback: ' + this.currentSpaId);
      return this.currentSpaId;
    }
  }

  // Primär: /spas/<id>/dashboard (originalintegrationens ändpunkt, GAMLA fältnamn:
  //   isOnline, isCelsius, rangeLimits, time som "HH:MM"-sträng, isPanelLocked)
  // Fallback: /web/spas/<id>/current-state (NYA fältnamn:
  //   online, celsius, setupParams, hour/minute separat, panelLock)
  //
  // spa.js förväntar sig genomgående de NYA fältnamnen (online, celsius,
  // setupParams, hour/minute, panelLock) - se isOnline()/useCelsius()/
  // getRangeLowTemp()/getTime()/isPanelLocked() i spa.js. Det betyder att
  // det är PRIMÄR-svaret (dashboard) som behöver normaliseras om till det
  // nya formatet när det används - INTE fallback-svaret, som redan är i
  // rätt format.
  async getSpa () {
    logDebug('Requesting spa data');

    let body;
    let usedFallback = false;

    try {
      const req = await client.get(
        `https://iot.controlmyspa.com/spas/${this.currentSpaId}/dashboard`,
        {
          headers: {
            Accept: '*/*',
            Authorization: 'Bearer ' + this.tokenData.accessToken
          }
        }
      );
      body = req.data.data;

      // Normalisera GAMLA fältnamn (dashboard) till de NYA fältnamn spa.js förväntar sig
      body.online = body.isOnline;
      body.celsius = body.isCelsius;
      body.panelLock = body.isPanelLocked;
      body.setupParams = body.rangeLimits;

      if (body.time && typeof body.time === 'string' && body.time.includes(':')) {
        const [h, m] = body.time.split(':').map(Number);
        body.hour = h;
        body.minute = m;
      }
    } catch (err) {
      logError(`Primary endpoint (dashboard) failed: ${err.message}. Trying fallback (web/current-state)...`);
      usedFallback = true;

      const fallbackReq = await client.get(
        `https://iot.controlmyspa.com/web/spas/${this.currentSpaId}/current-state`,
        {
          headers: {
            Accept: 'application/json, text/plain, */*',
            Authorization: 'Bearer ' + this.tokenData.accessToken
          }
        }
      );
      body = fallbackReq.data.data;
      // Inget att normalisera - current-state levererar redan de nya fältnamnen spa.js vill ha.
      logDebug('Used web/current-state fallback endpoint (already in expected field format)');
    }

    this.currentSpa = body;

    if (this.celsius) {
      this.currentSpa.desiredTemp = (
        (parseFloat(this.currentSpa.desiredTemp) - 32) *
        (5 / 9)
      ).toFixed(1);

      if (this.currentSpa.targetDesiredTemp == undefined || parseFloat(this.currentSpa.targetDesiredTemp) <= 0) {
        this.currentSpa.targetDesiredTemp = this.currentSpa.desiredTemp;
      } else {
        this.currentSpa.targetDesiredTemp = (
          (parseFloat(this.currentSpa.targetDesiredTemp) - 32) *
          (5 / 9)
        ).toFixed(1);
      }

      this.currentSpa.currentTemp = (
        (parseFloat(this.currentSpa.currentTemp) - 32) *
        (5 / 9)
      ).toFixed(1);
    }

    logDebug(`Current spa data: ${JSON.stringify(this.currentSpa)}`);
    return this.currentSpa;
  }

  async setTemp (temp) {
    let toSet = temp;
    if (this.celsius) {
      toSet = ((temp / 5) * 9 + 32).toFixed(1);
    }

    const tempData = {
      spaId: this.currentSpaId,
      value: parseFloat(toSet),
      via: 'MOBILE'
    };

    logDebug(`Setting spa temp, payload ${JSON.stringify(tempData)}`);

    const req = await client.post(
      'https://iot.controlmyspa.com/spa-commands/temperature/value',
      tempData,
      {
        headers: {
          Accept: 'application/json',
          'Content-Length': JSON.stringify(tempData).length,
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + this.tokenData.accessToken
        }
      }
    );

    if (req.status === 200) {
      const body = req.data.data;

      this.currentSpa.desiredTemp = body.command.values.DESIREDTEMP;
      if (this.celsius) {
        this.currentSpa.desiredTemp = (
          (parseFloat(body.command.values.DESIREDTEMP) - 32) *
          (5 / 9)
        ).toFixed(1);
      }
    } else {
      logError('failed to set spa temp');
    }

    return req.status === 200;
  }

  async setTempRangeHigh () {
    return await this.setTempRange(true);
  }

  async setTempRangeLow () {
    return await this.setTempRange(false);
  }

  sleep (ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async setTempRange (high) {

    const tempData = {
      range: high ? 'HIGH' : 'LOW',
      spaId: this.currentSpaId,
      via: 'MOBILE'
    };

    logDebug(`Setting temp range, payload ${JSON.stringify(tempData)}`);

    const req = await client.post(
      'https://iot.controlmyspa.com/spa-commands/temperature/range',
      tempData,
      {
        headers: {
          Accept: 'application/json',
          'Content-Length': JSON.stringify(tempData).length,
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + this.tokenData.accessToken
        }
      }
    );

    if (req.status === 200) {
      const oldRange = this.currentSpa.tempRange;

      if (this.waitForResult) {
        await this.sleep(3000);
        const newSpaData = await this.getSpa();

        logInfo(oldRange + ' => ' + newSpaData.tempRange);
        return newSpaData;
      }

      return true;
    } else {
      logError('Failed to set temp range');
    }

    return false;
  }

  async lockPanel () {
    return await this.setPanelLock(true);
  }

  async unlockPanel () {
    return await this.setPanelLock(false);
  }

  async setPanelLock (locked) {

    const panelData = {
      spaId: this.currentSpaId,
      state: locked ? 'LOCK_PANEL' : 'UNLOCK_PANEL',
      via: 'MOBILE'
    };

    logDebug(`Setting spa panel lock, payload ${JSON.stringify(panelData)}`);

    const req = await client.post(
      'https://iot.controlmyspa.com/spa-commands/panel/state',
      panelData,
      {
        headers: {
          Accept: 'application/json',
          'Content-Length': JSON.stringify(panelData).length,
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + this.tokenData.accessToken
        }
      }
    );

    if (req.status === 200) {
      const oldState = this.currentSpa.isPanelLocked;

      if (this.waitForResult) {
        await this.sleep(3000);
        const newSpaData = await this.getSpa();

        logInfo(
          (oldState ? 'LOCKED' : 'UNLOCKED') +
          ' => ' +
          (newSpaData.isPanelLocked ? 'LOCKED' : 'UNLOCKED')
        );

        return newSpaData;
      }

      return true;
    } else {
      logError('failed to set panel lock');
    }

    return false;
    }

    async setComponentState(logicalType, deviceNumber, desiredState) {

        const typeMap = {
            jet: 'PUMP',
            light: 'LIGHT',
            blower: 'BLOWER'
            // Add here
        };

        const hardwareType = typeMap[logicalType];
        if (!hardwareType) {
            throw new Error('Unknown logical component type: ${logicalType}');
        }

        // numbers 0,1,2  || states: HIGH , OFF
        if (desiredState !== 'OFF' && desiredState !== 'HIGH') {
            logError('Invalid value for desired state');
            return false;
        }

        const commandPayload = {
            componentType: logicalType,
            deviceNumber: Number(deviceNumber),
            spaId: this.currentSpaId,
            state: desiredState,
            via: 'MOBILE'
        };

        const req = await client.post(
            'https://iot.controlmyspa.com/spa-commands/component-state',
            commandPayload,
            {
                headers: {
                    'Content-Length': JSON.stringify(commandPayload).length,
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + this.tokenData.accessToken,
                }
            }
        );

        if (req.status === 200) {
            const oldState = this.currentSpa.components.find(
                (el, id) => {
                    return (
                        el.componentType === hardwareType && el.port === deviceNumber.toString()
                    );
                }
            );

            if (this.waitForResult) {
                await this.sleep(3000);
                const newSpaData = await this.getSpa();

                const newState = newSpaData.components.find((el, id) => {
                    return (
                        el.componentType === hardwareType && el.port === deviceNumber.toString()
                    );
                });

                logInfo(`${hardwareType} ${deviceNumber}: ${oldState?.value} => ${newState?.value}`);
                return newSpaData;
            }

            return true;
        } else {
            logError(`Failed to set ${logicalType} state`);
        }

        return false;
    }


  async setHeaterMode (desiredState) {

    // numbers 0,1,2  || states: HIGH , OFF
    if (desiredState !== 'REST' && desiredState !== 'READY') {
      logError('Invalid value for desired state');
      return false;
    }

    const heaterMode = {
      mode: desiredState,
      spaId: this.currentSpaId,
      via: 'MOBILE'
    };

    logDebug(`Setting heater mode, payload ${JSON.stringify(heaterMode)}`);

    const req = await client.post(
      'https://iot.controlmyspa.com/spa-commands/temperature/heater-mode',
      heaterMode,
      {
        headers: {
          Accept: 'application/json',
          'Content-Length': JSON.stringify(heaterMode).length,
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + this.tokenData.accessToken
        }
      }
    );

    if (req.status === 200) {
      const oldState = this.currentSpa.heaterMode;

      if (this.waitForResult) {
        await this.sleep(3000);
        const newSpaData = await this.getSpa();

        const newState = newSpaData.heaterMode;

        logInfo(oldState + ' => ' + newState);
        return newSpaData;
      }

      return true;
    } else {
      logError('Failed to set header mode');
    }

    return false;
    }

    async setFilterCycle2State(desiredState) {
        if (desiredState === "true") {
            desiredState = 'ON';
        } else if (desiredState === "false") {
            desiredState = 'OFF';
        } else {
            logError('Invalid value for desired state');
            return false;
        }

        const payload = {
            spaId: this.currentSpaId,
            state: desiredState,
            via: 'MOBILE'
        };

        try {
            const response = await client.post(
                'https://iot.controlmyspa.com/spa-commands/filter-cycles/toggle-filter2-state',
                payload,
                {
                    headers: {
                        Accept: 'application/json',
                        'Content-Length': JSON.stringify(payload).length,
                        'Content-Type': 'application/json',
                        Authorization: 'Bearer ' + this.tokenData.accessToken
                    }
                }
            );

        const body = response.data;

        if (
            response.status === 200 &&
            body?.statusCode === 200 &&
            body?.data?.success === true
        ) {
            logDebug('Filter cycle 2 state set successfully');
            return true;
        } else {
            logError('Unexpected response while setting filter cycle 2 state:', body);
        }
    } catch(err) {
        logError('Failed to set filter cycle 2 state:', err.message || err);
    }

    return false;
}

  async setFilterCycleIntervalSchedule (
    scheduleNumber,
    filterInterval,
    startTime
  ) {
      // scheduleNumber: 0 or 1
      // filterInterval: 196 (15 min intervals)
      // startTime: 'HH:mm'

    const schedule = {
      deviceNumber: Number(scheduleNumber),
      numOfIntervals: filterInterval,
      spaId: this.currentSpaId,
      time: startTime,
      via: 'MOBILE'
      };

      console.log('schedule', schedule);

      const response = await client.post(
        'https://iot.controlmyspa.com/spa-commands/filter-cycles/schedule',
        schedule,
        {
            headers: {
                Accept: 'application/json',
                'Content-Length': JSON.stringify(schedule).length,
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + this.tokenData.accessToken
            }
        }
      );

      const body = response.data;

      if (
          response.status === 200 &&
          body?.statusCode === 200 &&
          body?.data?.success === true
      ) {
          logInfo('Filter cycle schedule set successfully');
          return true;
      } else {
          logError('Unexpected response while setting filter cycle schedule:', body);
      }
    return false;
    }

    async setTime(dateTime) {
        if (!(dateTime instanceof Date)) {
            logError('Invalid input: expected Date object');
            return false;
        }
        const mm = String(dateTime.getMonth() + 1).padStart(2, '0');
        const dd = String(dateTime.getDate()).padStart(2, '0');
        const yyyy = dateTime.getFullYear();

        const hours = String(dateTime.getHours()).padStart(2, '0');
        const minutes = String(dateTime.getMinutes()).padStart(2, '0');

        const payload = {
            date: `${mm}/${dd}/${yyyy}`,
            time: `${hours}:${minutes}`,
            isMilitaryFormat: true,
            spaId: this.currentSpaId,
            via: 'MOBILE'
        };

        const response = await client.post(
            'https://iot.controlmyspa.com/spa-commands/time',
            payload,
            {
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                    Authorization: 'Bearer ' + this.tokenData.accessToken
                }
            }
        );

        const body = response.data;

        const resultOK =
            response.status === 200 &&
            body?.statusCode === 200 &&
            body?.data?.success === true;

        if (resultOK) {
            logInfo(`Time set successfully to ${payload.date} ${payload.time}`);
            return true;
        } else {
            logError('Failed to set time:', body);
            return false;
        }

    }

}

module.exports = ControlMySpa;
