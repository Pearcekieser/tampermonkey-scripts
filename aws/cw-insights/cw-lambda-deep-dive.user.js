// ==UserScript==
// @name         CW Insights - Lambda Deep Dive
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Add a link to any UUID in cloudwatch logs to make a new query that filters on that uuid
// @author       Pearce Kieser
// @match        https://*.console.aws.amazon.com/cloudwatch/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=amazon.com
// @require      https://cdn.jsdelivr.net/npm/dayjs@1/dayjs.min.js
// @updateURL    https://github.com/Pearcekieser/tampermonkey-scripts/raw/main/aws/cw-insights/cw-lambda-deep-dive.user.js
// @downloadURL  https://github.com/Pearcekieser/tampermonkey-scripts/raw/main/aws/cw-insights/cw-lambda-deep-dive.user.js
// @grant        none
// ==/UserScript==

// Parse queries based on https://stackoverflow.com/questions/60796991/is-there-a-way-to-generate-the-aws-console-urls-for-cloudwatch-log-group-filters
// Another cool example (always click the run button): https://github.com/ambanum/DevTools/blob/main/tampermonkey/cloudwatch.js


// test url: https://us-west-2.console.aws.amazon.com/cloudwatch/home?region=us-west-2#logsV2:logs-insights$3FqueryDetail$3D~(end~'2021-11-27T04*3a59*3a59.000Z~start~'2021-11-26T05*3a00*3a00.000Z~timeType~'ABSOLUTE~tz~'LOCAL~editorString~'fields*20*40timestamp*2c*20*40message*0a*7c*20sort*20*40timestamp*20desc*0a*7c*20limit*2020*0a~queryId~'ead0409a1d8e7f70-d55cab82-4f2612a-1bb95f-e94a22a9d2582187f6f083d7~source~(~'*2faws*2flambda*2fHelloLambda1~'*2faws*2flambda*2fHelloLambda2))

// TODOs
// P0 - DONE - Extract log groups, region, etc from existing URL
// P0 - DONE - Generate desired query based off of uuid match
// P0 - DONE - prevent double wrapping in <a> tags
// P1 - DONE - Automatically limit resutls to within 15min of the selected records timestamp
// P1 - update running to listen to changes on tbody.logs-table__body in the iframe
// P1 - tamper monkey setting for the time range around timestamp (grab timestamp from the neighboring tr element and profit)
// P1 - check for errors
// P2 - add hosting for the script (github + raw links probalby work great)
// P2 - update the configuration for the script so it automatically pulls the latest update



(function() {
  'use strict';

  const uuidRegex = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
  const timestampRegex = /(\d{4}-[01]\d-[0-3]\d[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-][0-2]\d:[0-5]\d))/;

  function parseInsightsUrl(url) {
      // Decodes the URL components
      const decode = (s) => decodeURIComponent(s.replace(/\*/g, '%').replace(/\$/g, '%'));

      // Extracts the region
      const regionMatch = url.match(/region=([^&]+)#/);
      if (!regionMatch) {
          throw new Error('Invalid URL: Unable to find the region');
      }
      const region = regionMatch[1];

      // Handles the part after the hash
      const hashComponents = url.split('#');
      if (hashComponents.length < 2) {
          throw new Error('Invalid URL: Unable to find the hash components');
      }
      // Decoding the fragment
      const hashPartDecoded = decode(hashComponents[1]);

      // Extracts the queryDetail
      const queryDetailMatch = hashPartDecoded.match(/queryDetail=([^)]+)/);
      if (!queryDetailMatch) {
          throw new Error('Invalid URL: Unable to find the queryDetail');
      }
      const queryDetail = queryDetailMatch[1];

      // Parsing individual components from the queryDetail
      const endMatch = queryDetail.match(/end~'([^~]+)~/);
      const startMatch = queryDetail.match(/start~'([^~]+)~/);
      const timeTypeMatch = queryDetail.match(/timeType~'([^~]+)~/);
      const tzMatch = queryDetail.match(/tz~'([^~]+)~/);
      const editorStringMatch = queryDetail.match(/editorString~'([^~]+)~/);
      const queryIdMatch = queryDetail.match(/queryId~'([^~]+)~/);
      const sourceMatch = queryDetail.match(/source~\(([^)]+)/);

      const sourceArray = sourceMatch ? sourceMatch[1].match(/~'([^~']+)/g)
          .map(match => match.substring(2)) : null;

      return {
          region: region,
          end: endMatch ? decode(endMatch[1]) : null,
          start: startMatch ? decode(startMatch[1]) : null,
          timeType: timeTypeMatch ? decode(timeTypeMatch[1]) : null,
          timeZone: tzMatch ? decode(tzMatch[1]) : null,
          editorString: editorStringMatch ? decode(editorStringMatch[1]) : null,
          queryId: queryIdMatch ? decode(queryIdMatch[1]) : null,
          sourceGroups: sourceArray ? sourceArray : null
      };
  }

  function buildInsightsUrl(data) {
      // Encodes components to make them URL safe
      const encode = (s) => encodeURIComponent(s).replace(/%/g, '*').replace(/\$/g, '$');

      // Constructs the base URL with the region
      let url = `https://${data.region}.console.aws.amazon.com/cloudwatch/home?region=${encode(data.region)}#logsV2:logs-insights`;

      // Encodes and assembles the details after the hash
      let hashDetails = `$3FqueryDetail$3D~(`;
      if (data.end) hashDetails += `end~'${encode(data.end)}~`;
      if (data.start) hashDetails += `start~'${encode(data.start)}~`;
      if (data.timeType) hashDetails += `timeType~'${encode(data.timeType)}~`;
      if (data.timeZone) hashDetails += `tz~'${encode(data.timeZone)}~`;
      if (data.editorString) hashDetails += `editorString~'${encode(data.editorString)}~`;
      if (data.queryId) hashDetails += `queryId~'${encode(data.queryId)}~`;

      // Handles the source group
      if (data.sourceGroups && data.sourceGroups.length > 0) {
          const encodedSources = data.sourceGroups.map(src => `~'${encode(src)}`);
          hashDetails += `source~(${encodedSources.join('')})`;
      }

      hashDetails += ')'; // Closing the double parentheses

      // Appends the encoded details after the hash
      url += hashDetails;

      return url;
  }


  function generateDesiredQuery(uuid) {
      return `fields @timestamp, @message\n| sort @timestamp desc\n| filter @message like '${uuid}'\n`
  }

  function replaceUUIDs() {
      const urlInfo = parseInsightsUrl(window.location.href);

      const newUrl = buildInsightsUrl(urlInfo);

      const iframe = document.querySelector('#microConsole-Logs');
      if (iframe) {
          const insideIframe = iframe.contentDocument || iframe.contentWindow.document;
          const targetNode = insideIframe.querySelector('tbody.logs-table__body');
          if (targetNode) {
              targetNode.querySelectorAll('tr').forEach(tr => {

                  // Get the HTML content of the row
                  let html = tr.innerHTML;

                  // Replace UUIDs not already part of an <a> tag
                  html = html.replace(uuidRegex, function(match) {
                      // Check if the UUID is already wrapped with an <a> tag
                      const alreadyReplacedRegex = new RegExp(`<a[^>]*>${match}</a>`);
                      if (alreadyReplacedRegex.test(html)) {
                          // If it's already replaced, return the match without modification
                          return match;
                      } else {
                          console.log(html);
                          let timestamp = null;
                          const timestampMatch = html.match(timestampRegex);
                          console.log(timestampMatch);
                          if (timestampMatch) {
                              timestamp = dayjs(timestampMatch[1])
                          }
                          const newQuery = generateDesiredQuery(match);
                          urlInfo.editorString = newQuery;
                          if (timestamp) {
                              console.log(timestamp.toISOString())
                              console.log(timestamp.add(15, 'minute').toISOString())
                              console.log(timestamp.subtract(15, 'minute').toISOString())
                              urlInfo.start = timestamp.subtract(15, 'minute').toISOString();
                              urlInfo.end = timestamp.add(15, 'minute').toISOString();
                          }
                          const newUrl = buildInsightsUrl(urlInfo);

                          // If it's not replaced, return the new <a> tag
                          return `<a href="${newUrl}" target="_blank">${match}</a>`;
                      }
                  });

                  // Update the HTML content of the row
                  if (tr.innerHTML !== html) {
                      tr.innerHTML = html;
                  }
              });
          }
      }
  }

  // Run replaceUUIDs every 1 second
  setInterval(replaceUUIDs, 500);
})();
