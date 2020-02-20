const _ = require('lodash');
const jwt = require('jsonwebtoken');

// https://gist.github.com/kurtsson/3f1c8efc0ccd549c9e31
const formatXml = function(xml) {
  var formatted = '';
  var reg = /(>)(<)(\/*)/g;
  xml = xml.toString().replace(reg, '$1\r\n$2$3');
  var pad = 0;
  var nodes = xml.split('\r\n');
  for(var n in nodes) {
    var node = nodes[n];
    var indent = 0;
    if (node.match(/.+<\/\w[^>]*>$/)) {
      indent = 0;
    } else if (node.match(/^<\/\w/)) {
      if (pad !== 0) {
        pad -= 1;
      }
    } else if (node.match(/^<\w[^>]*[^\/]>.*$/)) {
      indent = 1;
    } else {
      indent = 0;
    }

    var padding = '';
    for (var i = 0; i < pad; i++) {
      padding += '  ';
    }

    formatted += padding + node + '\r\n';
    pad += indent;
  }

  return formatted.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/ /g, '&nbsp;');
};

const highlight = function(json) {
  if (typeof json != 'string') {
    json = JSON.stringify(json, undefined, 2);
  }
  json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (match) => {
    let cls = 'json-value';
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        cls = 'json-key';
      } else {
        cls = 'json-string';
      }
    } else if (/true|false/.test(match)) {
      cls = 'json-value';
    }
    return '<span class="' + cls + '">' + match + '</span>';
  });
};

module.exports.wsFedResult = function(response) {
  if (!response|| !response.length) {
    return null;
  }

  try {
    return formatXml(response);
  } catch(e) {
    return response;
  }
}

module.exports.samlResponse = function(response) {
  if (!response || !response.length) {
    return null;
  }

  try {
    const xml = new Buffer(response, 'base64').toString();
    return formatXml(xml);
  } catch(e) {
    return response;
  }
}

module.exports.jwt = function(token) {
  if (!token || token.indexOf('ey') !== 0) {
    return null;
  }

  try {
    const decoded = jwt.decode(token, { complete: true });
    return highlight(decoded);
  } catch(e) {
    return token;
  }
}

module.exports.base64url = function(b) {
  return b.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

module.exports.syntaxHighlight = function(obj) {
  try {
    const keys = _.keys(obj);
    if (!keys.length) {
      return null;
    }

    const orderedObject = {};
    keys.sort().forEach((key) => {
      orderedObject[key] = obj[key];
    });

    return highlight(orderedObject);
  } catch(e) {
    return JSON.stringify(obj, null, 2);
  }
}

module.exports.tryParseJSON = function(string) {
  try {
    return JSON.parse(string);
  } catch (e) {
    return;
  }
}