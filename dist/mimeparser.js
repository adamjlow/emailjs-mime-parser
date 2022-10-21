'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.MimeNode = exports.NodeCounter = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

exports.default = parse;

var _ramda = require('ramda');

var _timezones = require('./timezones');

var _timezones2 = _interopRequireDefault(_timezones);

var _emailjsMimeCodec = require('emailjs-mime-codec');

var _textEncoding = require('text-encoding');

var _emailjsAddressparser = require('emailjs-addressparser');

var _emailjsAddressparser2 = _interopRequireDefault(_emailjsAddressparser);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
 * Counts MIME nodes to prevent memory exhaustion attacks (CWE-400)
 * see: https://snyk.io/vuln/npm:emailjs-mime-parser:20180625
 */
var MAXIMUM_NUMBER_OF_MIME_NODES = 999;

var NodeCounter = exports.NodeCounter = function () {
  function NodeCounter() {
    _classCallCheck(this, NodeCounter);

    this.count = 0;
  }

  _createClass(NodeCounter, [{
    key: 'bump',
    value: function bump() {
      if (++this.count > MAXIMUM_NUMBER_OF_MIME_NODES) {
        throw new Error('Maximum number of MIME nodes exceeded!');
      }
    }
  }]);

  return NodeCounter;
}();

function forEachLine(str, callback) {
  var line = '';
  var terminator = '';
  for (var i = 0; i < str.length; i += 1) {
    var char = str[i];
    if (char === '\r' || char === '\n') {
      var nextChar = str[i + 1];
      terminator += char;
      // Detect Windows and Macintosh line terminators.
      if (terminator + nextChar === '\r\n' || terminator + nextChar === '\n\r') {
        callback(line, terminator + nextChar);
        line = '';
        terminator = '';
        i += 1;
        // Detect single-character terminators, like Linux or other system.
      } else if (terminator === '\n' || terminator === '\r') {
        callback(line, terminator);
        line = '';
        terminator = '';
      }
    } else {
      line += char;
    }
  }
  // Flush the line and terminator values if necessary; handle edge cases where MIME is generated without last line terminator.
  if (line !== '' || terminator !== '') {
    callback(line, terminator);
  }
}

function parse(chunk) {
  var root = new MimeNode(new NodeCounter());
  var str = typeof chunk === 'string' ? chunk : String.fromCharCode.apply(null, chunk);
  forEachLine(str, function (line, terminator) {
    root.writeLine(line, terminator);
  });
  root.finalize();
  return root;
}

var MimeNode = exports.MimeNode = function () {
  function MimeNode() {
    var nodeCounter = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : new NodeCounter();

    _classCallCheck(this, MimeNode);

    this.nodeCounter = nodeCounter;
    this.nodeCounter.bump();

    this.header = []; // An array of unfolded header lines
    this.headers = {}; // An object that holds header key=value pairs
    this.bodystructure = '';
    this.childNodes = []; // If this is a multipart or message/rfc822 mime part, the value will be converted to array and hold all child nodes for this node
    this.raw = ''; // Stores the raw content of this node

    this._state = 'HEADER'; // Current state, always starts out with HEADER
    this._bodyBuffer = ''; // Body buffer
    this._lineCount = 0; // Line counter bor the body part
    this._currentChild = false; // Active child node (if available)
    this._lineRemainder = ''; // Remainder string when dealing with base64 and qp values
    this._isMultipart = false; // Indicates if this is a multipart node
    this._multipartBoundary = false; // Stores boundary value for current multipart node
    this._isRfc822 = false; // Indicates if this is a message/rfc822 node
  }

  _createClass(MimeNode, [{
    key: 'writeLine',
    value: function writeLine(line, terminator) {
      this.raw += line + (terminator || '\n');

      if (this._state === 'HEADER') {
        this._processHeaderLine(line);
      } else if (this._state === 'BODY') {
        this._processBodyLine(line, terminator);
      }
    }
  }, {
    key: 'finalize',
    value: function finalize() {
      var _this = this;

      if (this._isRfc822) {
        // Some DSN's lack body despite rfc822 and lack newline to identify head of headers, capture and fix here
        if (this._currentChild._state === 'HEADER') {
          this._currentChild.writeLine('');
        }
        this._currentChild.finalize();
      } else {
        this._emitBody();
      }

      this.bodystructure = this.childNodes.reduce(function (agg, child) {
        return agg + '--' + _this._multipartBoundary + '\n' + child.bodystructure;
      }, this.header.join('\n') + '\n\n') + (this._multipartBoundary ? '--' + this._multipartBoundary + '--\n' : '');
    }
  }, {
    key: '_decodeBodyBuffer',
    value: function _decodeBodyBuffer() {
      switch (this.contentTransferEncoding.value) {
        case 'base64':
          this._bodyBuffer = (0, _emailjsMimeCodec.base64Decode)(this._bodyBuffer, this.charset);
          break;
        case 'quoted-printable':
          {
            this._bodyBuffer = this._bodyBuffer.replace(/=(\r?\n|$)/g, '').replace(/=([a-f0-9]{2})/ig, function (m, code) {
              return String.fromCharCode(parseInt(code, 16));
            });
            break;
          }
      }
    }

    /**
     * Processes a line in the HEADER state. It the line is empty, change state to BODY
     *
     * @param {String} line Entire input line as 'binary' string
     */

  }, {
    key: '_processHeaderLine',
    value: function _processHeaderLine(line) {
      if (!line) {
        this._parseHeaders();
        this.bodystructure += this.header.join('\n') + '\n\n';
        this._state = 'BODY';
        return;
      }

      if (line.match(/^\s/) && this.header.length) {
        this.header[this.header.length - 1] += '\n' + line;
      } else {
        this.header.push(line);
      }
    }

    /**
     * Joins folded header lines and calls Content-Type and Transfer-Encoding processors
     */

  }, {
    key: '_parseHeaders',
    value: function _parseHeaders() {
      for (var hasBinary = false, i = 0, len = this.header.length; i < len; i++) {
        var value = this.header[i].split(':');
        var key = (value.shift() || '').trim().toLowerCase();
        value = (value.join(':') || '').replace(/\n/g, '').trim();

        if (value.match(/[\u0080-\uFFFF]/)) {
          if (!this.charset) {
            hasBinary = true;
          }
          // use default charset at first and if the actual charset is resolved, the conversion is re-run
          value = (0, _emailjsMimeCodec.decode)((0, _emailjsMimeCodec.convert)(str2arr(value), this.charset || 'iso-8859-1'));
        }

        this.headers[key] = (this.headers[key] || []).concat([this._parseHeaderValue(key, value)]);

        if (!this.charset && key === 'content-type') {
          this.charset = this.headers[key][this.headers[key].length - 1].params.charset;
        }

        if (hasBinary && this.charset) {
          // reset values and start over once charset has been resolved and 8bit content has been found
          hasBinary = false;
          this.headers = {};
          i = -1; // next iteration has i == 0
        }
      }

      this.fetchContentType();
      this._processContentTransferEncoding();
    }

    /**
     * Parses single header value
     * @param {String} key Header key
     * @param {String} value Value for the key
     * @return {Object} parsed header
     */

  }, {
    key: '_parseHeaderValue',
    value: function _parseHeaderValue(key, value) {
      var parsedValue = void 0;
      var isAddress = false;

      switch (key) {
        case 'content-type':
        case 'content-transfer-encoding':
        case 'content-disposition':
        case 'dkim-signature':
          parsedValue = (0, _emailjsMimeCodec.parseHeaderValue)(value);
          break;
        case 'from':
        case 'sender':
        case 'to':
        case 'reply-to':
        case 'cc':
        case 'bcc':
        case 'abuse-reports-to':
        case 'errors-to':
        case 'return-path':
        case 'delivered-to':
          isAddress = true;
          parsedValue = {
            value: [].concat((0, _emailjsAddressparser2.default)(value) || [])
          };
          break;
        case 'date':
          parsedValue = {
            value: this._parseDate(value)
          };
          break;
        default:
          parsedValue = {
            value: value
          };
      }
      parsedValue.initial = value;

      this._decodeHeaderCharset(parsedValue, { isAddress: isAddress });

      return parsedValue;
    }

    /**
     * Checks if a date string can be parsed. Falls back replacing timezone
     * abbrevations with timezone values. Bogus timezones default to UTC.
     *
     * @param {String} str Date header
     * @returns {String} UTC date string if parsing succeeded, otherwise returns input value
     */

  }, {
    key: '_parseDate',
    value: function _parseDate() {
      var str = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';

      var date = new Date(str.trim().replace(/\b[a-z]+$/i, function (tz) {
        return _timezones2.default[tz.toUpperCase()] || '+0000';
      }));
      return date.toString() !== 'Invalid Date' ? date.toUTCString().replace(/GMT/, '+0000') : str;
    }
  }, {
    key: '_decodeHeaderCharset',
    value: function _decodeHeaderCharset(parsed) {
      var _this2 = this;

      var _ref = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {},
          isAddress = _ref.isAddress;

      // decode default value
      if (typeof parsed.value === 'string') {
        parsed.value = (0, _emailjsMimeCodec.mimeWordsDecode)(parsed.value);
      }

      // decode possible params
      Object.keys(parsed.params || {}).forEach(function (key) {
        if (typeof parsed.params[key] === 'string') {
          parsed.params[key] = (0, _emailjsMimeCodec.mimeWordsDecode)(parsed.params[key]);
        }
      });

      // decode addresses
      if (isAddress && Array.isArray(parsed.value)) {
        parsed.value.forEach(function (addr) {
          if (addr.name) {
            addr.name = (0, _emailjsMimeCodec.mimeWordsDecode)(addr.name);
            if (Array.isArray(addr.group)) {
              _this2._decodeHeaderCharset({ value: addr.group }, { isAddress: true });
            }
          }
        });
      }

      return parsed;
    }

    /**
     * Parses Content-Type value and selects following actions.
     */

  }, {
    key: 'fetchContentType',
    value: function fetchContentType() {
      var defaultValue = (0, _emailjsMimeCodec.parseHeaderValue)('text/plain');
      this.contentType = (0, _ramda.pathOr)(defaultValue, ['headers', 'content-type', '0'])(this);
      this.contentType.value = (this.contentType.value || '').toLowerCase().trim();
      this.contentType.type = this.contentType.value.split('/').shift() || 'text';

      if (this.contentType.params && this.contentType.params.charset && !this.charset) {
        this.charset = this.contentType.params.charset;
      }

      if (this.contentType.type === 'multipart' && this.contentType.params.boundary) {
        this.childNodes = [];
        this._isMultipart = this.contentType.value.split('/').pop() || 'mixed';
        this._multipartBoundary = this.contentType.params.boundary;
      }

      /**
       * For attachment (inline/regular) if charset is not defined and attachment is non-text/*,
       * then default charset to binary.
       * Refer to issue: https://github.com/emailjs/emailjs-mime-parser/issues/18
       */
      var defaultContentDispositionValue = (0, _emailjsMimeCodec.parseHeaderValue)('');
      var contentDisposition = (0, _ramda.pathOr)(defaultContentDispositionValue, ['headers', 'content-disposition', '0'])(this);
      var isAttachment = (contentDisposition.value || '').toLowerCase().trim() === 'attachment';
      var isInlineAttachment = (contentDisposition.value || '').toLowerCase().trim() === 'inline';
      if ((isAttachment || isInlineAttachment) && this.contentType.type !== 'text' && !this.charset) {
        this.charset = 'binary';
      }

      if (this.contentType.value === 'message/rfc822' && !isAttachment) {
        /**
         * Parse message/rfc822 only if the mime part is not marked with content-disposition: attachment,
         * otherwise treat it like a regular attachment
         */
        this._currentChild = new MimeNode(this.nodeCounter);
        this.childNodes = [this._currentChild];
        this._isRfc822 = true;
      }
    }

    /**
     * Parses Content-Transfer-Encoding value to see if the body needs to be converted
     * before it can be emitted
     */

  }, {
    key: '_processContentTransferEncoding',
    value: function _processContentTransferEncoding() {
      var defaultValue = (0, _emailjsMimeCodec.parseHeaderValue)('7bit');
      this.contentTransferEncoding = (0, _ramda.pathOr)(defaultValue, ['headers', 'content-transfer-encoding', '0'])(this);
      this.contentTransferEncoding.value = (0, _ramda.pathOr)('', ['contentTransferEncoding', 'value'])(this).toLowerCase().trim();
    }

    /**
     * Processes a line in the BODY state. If this is a multipart or rfc822 node,
     * passes line value to child nodes.
     *
     * @param {String} line Entire input line as 'binary' string
     * @param {String} terminator The line terminator detected by parser
     */

  }, {
    key: '_processBodyLine',
    value: function _processBodyLine(line, terminator) {
      if (this._isMultipart) {
        if (line === '--' + this._multipartBoundary) {
          this.bodystructure += line + '\n';
          if (this._currentChild) {
            this._currentChild.finalize();
          }
          this._currentChild = new MimeNode(this.nodeCounter);
          this.childNodes.push(this._currentChild);
        } else if (line === '--' + this._multipartBoundary + '--') {
          this.bodystructure += line + '\n';
          if (this._currentChild) {
            this._currentChild.finalize();
          }
          this._currentChild = false;
        } else if (this._currentChild) {
          this._currentChild.writeLine(line, terminator);
        } else {
          // Ignore multipart preamble
        }
      } else if (this._isRfc822) {
        this._currentChild.writeLine(line, terminator);
      } else {
        this._lineCount++;

        switch (this.contentTransferEncoding.value) {
          case 'base64':
            this._bodyBuffer += line + terminator;
            break;
          case 'quoted-printable':
            {
              var curLine = this._lineRemainder + line + terminator;
              var match = curLine.match(/=[a-f0-9]{0,1}$/i);
              if (match) {
                this._lineRemainder = match[0];
                curLine = curLine.substr(0, curLine.length - this._lineRemainder.length);
              } else {
                this._lineRemainder = '';
              }
              this._bodyBuffer += curLine;
              break;
            }
          case '7bit':
          case '8bit':
          default:
            this._bodyBuffer += line + terminator;
            break;
        }
      }
    }

    /**
     * Emits a chunk of the body
    */

  }, {
    key: '_emitBody',
    value: function _emitBody() {
      this._decodeBodyBuffer();
      if (this._isMultipart || !this._bodyBuffer) {
        return;
      }

      this._processFlowedText();
      this.content = str2arr(this._bodyBuffer);
      this._processHtmlText();
      this._bodyBuffer = '';
    }
  }, {
    key: '_processFlowedText',
    value: function _processFlowedText() {
      var isText = /^text\/(plain|html)$/i.test(this.contentType.value);
      var isFlowed = /^flowed$/i.test((0, _ramda.pathOr)('', ['contentType', 'params', 'format'])(this));
      if (!isText || !isFlowed) return;

      var delSp = /^yes$/i.test(this.contentType.params.delsp);
      var bodyBuffer = '';

      forEachLine(this._bodyBuffer, function (line, terminator) {
        // remove soft linebreaks after space symbols.
        // delsp adds spaces to text to be able to fold it.
        // these spaces can be removed once the text is unfolded
        var endsWithSpace = / $/.test(line);
        var isBoundary = /(^|\n)-- $/.test(line);

        bodyBuffer += (delSp ? line.replace(/[ ]+$/, '') : line) + (endsWithSpace && !isBoundary ? '' : terminator);
      });

      this._bodyBuffer = bodyBuffer.replace(/^ /gm, ''); // remove whitespace stuffing http://tools.ietf.org/html/rfc3676#section-4.4
    }
  }, {
    key: '_processHtmlText',
    value: function _processHtmlText() {
      var contentDisposition = this.headers['content-disposition'] && this.headers['content-disposition'][0] || (0, _emailjsMimeCodec.parseHeaderValue)('');
      var isHtml = /^text\/(plain|html)$/i.test(this.contentType.value);
      var isAttachment = /^attachment$/i.test(contentDisposition.value);
      if (isHtml && !isAttachment) {
        if (!this.charset && /^text\/html$/i.test(this.contentType.value)) {
          this.charset = this.detectHTMLCharset(this._bodyBuffer);
        }

        // decode "binary" string to an unicode string
        if (!/^utf[-_]?8$/i.test(this.charset)) {
          this.content = (0, _emailjsMimeCodec.convert)(str2arr(this._bodyBuffer), this.charset || 'iso-8859-1');
        } else if (this.contentTransferEncoding.value === 'base64') {
          this.content = utf8Str2arr(this._bodyBuffer);
        }

        // override charset for text nodes
        this.charset = this.contentType.params.charset = 'utf-8';
      }
    }

    /**
     * Detect charset from a html file
     *
     * @param {String} html Input HTML
     * @returns {String} Charset if found or undefined
     */

  }, {
    key: 'detectHTMLCharset',
    value: function detectHTMLCharset(html) {
      var charset = void 0,
          input = void 0;

      html = html.replace(/\r?\n|\r/g, ' ');
      var meta = html.match(/<meta\s+http-equiv=["'\s]*content-type[^>]*?>/i);
      if (meta) {
        input = meta[0];
      }

      if (input) {
        charset = input.match(/charset\s?=\s?([a-zA-Z\-_:0-9]*);?/);
        if (charset) {
          charset = (charset[1] || '').trim().toLowerCase();
        }
      }

      meta = html.match(/<meta\s+charset=["'\s]*([^"'<>/\s]+)/i);
      if (!charset && meta) {
        charset = (meta[1] || '').trim().toLowerCase();
      }

      return charset;
    }
  }]);

  return MimeNode;
}();

var str2arr = function str2arr(str) {
  return new Uint8Array(str.split('').map(function (char) {
    return char.charCodeAt(0);
  }));
};
var utf8Str2arr = function utf8Str2arr(str) {
  return new _textEncoding.TextEncoder('utf-8').encode(str);
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9taW1lcGFyc2VyLmpzIl0sIm5hbWVzIjpbInBhcnNlIiwiTUFYSU1VTV9OVU1CRVJfT0ZfTUlNRV9OT0RFUyIsIk5vZGVDb3VudGVyIiwiY291bnQiLCJFcnJvciIsImZvckVhY2hMaW5lIiwic3RyIiwiY2FsbGJhY2siLCJsaW5lIiwidGVybWluYXRvciIsImkiLCJsZW5ndGgiLCJjaGFyIiwibmV4dENoYXIiLCJjaHVuayIsInJvb3QiLCJNaW1lTm9kZSIsIlN0cmluZyIsImZyb21DaGFyQ29kZSIsImFwcGx5Iiwid3JpdGVMaW5lIiwiZmluYWxpemUiLCJub2RlQ291bnRlciIsImJ1bXAiLCJoZWFkZXIiLCJoZWFkZXJzIiwiYm9keXN0cnVjdHVyZSIsImNoaWxkTm9kZXMiLCJyYXciLCJfc3RhdGUiLCJfYm9keUJ1ZmZlciIsIl9saW5lQ291bnQiLCJfY3VycmVudENoaWxkIiwiX2xpbmVSZW1haW5kZXIiLCJfaXNNdWx0aXBhcnQiLCJfbXVsdGlwYXJ0Qm91bmRhcnkiLCJfaXNSZmM4MjIiLCJfcHJvY2Vzc0hlYWRlckxpbmUiLCJfcHJvY2Vzc0JvZHlMaW5lIiwiX2VtaXRCb2R5IiwicmVkdWNlIiwiYWdnIiwiY2hpbGQiLCJqb2luIiwiY29udGVudFRyYW5zZmVyRW5jb2RpbmciLCJ2YWx1ZSIsImNoYXJzZXQiLCJyZXBsYWNlIiwibSIsImNvZGUiLCJwYXJzZUludCIsIl9wYXJzZUhlYWRlcnMiLCJtYXRjaCIsInB1c2giLCJoYXNCaW5hcnkiLCJsZW4iLCJzcGxpdCIsImtleSIsInNoaWZ0IiwidHJpbSIsInRvTG93ZXJDYXNlIiwic3RyMmFyciIsImNvbmNhdCIsIl9wYXJzZUhlYWRlclZhbHVlIiwicGFyYW1zIiwiZmV0Y2hDb250ZW50VHlwZSIsIl9wcm9jZXNzQ29udGVudFRyYW5zZmVyRW5jb2RpbmciLCJwYXJzZWRWYWx1ZSIsImlzQWRkcmVzcyIsIl9wYXJzZURhdGUiLCJpbml0aWFsIiwiX2RlY29kZUhlYWRlckNoYXJzZXQiLCJkYXRlIiwiRGF0ZSIsInRpbWV6b25lIiwidHoiLCJ0b1VwcGVyQ2FzZSIsInRvU3RyaW5nIiwidG9VVENTdHJpbmciLCJwYXJzZWQiLCJPYmplY3QiLCJrZXlzIiwiZm9yRWFjaCIsIkFycmF5IiwiaXNBcnJheSIsImFkZHIiLCJuYW1lIiwiZ3JvdXAiLCJkZWZhdWx0VmFsdWUiLCJjb250ZW50VHlwZSIsInR5cGUiLCJib3VuZGFyeSIsInBvcCIsImRlZmF1bHRDb250ZW50RGlzcG9zaXRpb25WYWx1ZSIsImNvbnRlbnREaXNwb3NpdGlvbiIsImlzQXR0YWNobWVudCIsImlzSW5saW5lQXR0YWNobWVudCIsImN1ckxpbmUiLCJzdWJzdHIiLCJfZGVjb2RlQm9keUJ1ZmZlciIsIl9wcm9jZXNzRmxvd2VkVGV4dCIsImNvbnRlbnQiLCJfcHJvY2Vzc0h0bWxUZXh0IiwiaXNUZXh0IiwidGVzdCIsImlzRmxvd2VkIiwiZGVsU3AiLCJkZWxzcCIsImJvZHlCdWZmZXIiLCJlbmRzV2l0aFNwYWNlIiwiaXNCb3VuZGFyeSIsImlzSHRtbCIsImRldGVjdEhUTUxDaGFyc2V0IiwidXRmOFN0cjJhcnIiLCJodG1sIiwiaW5wdXQiLCJtZXRhIiwiVWludDhBcnJheSIsIm1hcCIsImNoYXJDb2RlQXQiLCJUZXh0RW5jb2RlciIsImVuY29kZSJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O2tCQW9Ed0JBLEs7O0FBcER4Qjs7QUFDQTs7OztBQUNBOztBQUNBOztBQUNBOzs7Ozs7OztBQUVBOzs7O0FBSUEsSUFBTUMsK0JBQStCLEdBQXJDOztJQUNhQyxXLFdBQUFBLFc7QUFDWCx5QkFBZTtBQUFBOztBQUNiLFNBQUtDLEtBQUwsR0FBYSxDQUFiO0FBQ0Q7Ozs7MkJBQ087QUFDTixVQUFJLEVBQUUsS0FBS0EsS0FBUCxHQUFlRiw0QkFBbkIsRUFBaUQ7QUFDL0MsY0FBTSxJQUFJRyxLQUFKLENBQVUsd0NBQVYsQ0FBTjtBQUNEO0FBQ0Y7Ozs7OztBQUdILFNBQVNDLFdBQVQsQ0FBc0JDLEdBQXRCLEVBQTJCQyxR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QSxHQUFsQixDQUFmLENBQVA7QUFBQSxDQUFoQjtBQUNBLElBQU1OLGNBQWMsU0FBZEEsV0FBYztBQUFBLFNBQU8sSUFBSU8seUJBQUosQ0FBZ0IsT0FBaEIsRUFBeUJDLE1BQXpCLENBQWdDbkgsR0FBaEMsQ0FBUDtBQUFBLENBQXBCIiwiZmlsZSI6Im1pbWVwYXJzZXIuanMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBwYXRoT3IgfSBmcm9tICdyYW1kYSdcbmltcG9ydCB0aW1lem9uZSBmcm9tICcuL3RpbWV6b25lcydcbmltcG9ydCB7IGRlY29kZSwgYmFzZTY0RGVjb2RlLCBjb252ZXJ0LCBwYXJzZUhlYWRlclZhbHVlLCBtaW1lV29yZHNEZWNvZGUgfSBmcm9tICdlbWFpbGpzLW1pbWUtY29kZWMnXG5pbXBvcnQgeyBUZXh0RW5jb2RlciB9IGZyb20gJ3RleHQtZW5jb2RpbmcnXG5pbXBvcnQgcGFyc2VBZGRyZXNzIGZyb20gJ2VtYWlsanMtYWRkcmVzc3BhcnNlcidcblxuLypcbiAqIENvdW50cyBNSU1FIG5vZGVzIHRvIHByZXZlbnQgbWVtb3J5IGV4aGF1c3Rpb24gYXR0YWNrcyAoQ1dFLTQwMClcbiAqIHNlZTogaHR0cHM6Ly9zbnlrLmlvL3Z1bG4vbnBtOmVtYWlsanMtbWltZS1wYXJzZXI6MjAxODA2MjVcbiAqL1xuY29uc3QgTUFYSU1VTV9OVU1CRVJfT0ZfTUlNRV9OT0RFUyA9IDk5OVxuZXhwb3J0IGNsYXNzIE5vZGVDb3VudGVyIHtcbiAgY29uc3RydWN0b3IgKCkge1xuICAgIHRoaXMuY291bnQgPSAwXG4gIH1cbiAgYnVtcCAoKSB7XG4gICAgaWYgKCsrdGhpcy5jb3VudCA+IE1BWElNVU1fTlVNQkVSX09GX01JTUVfTk9ERVMpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignTWF4aW11bSBudW1iZXIgb2YgTUlNRSBub2RlcyBleGNlZWRlZCEnKVxuICAgIH1cbiAgfVxufVxuXG5mdW5jdGlvbiBmb3JFYWNoTGluZSAoc3RyLCBjYWxsYmFjaykge1xuICBsZXQgbGluZSA9ICcnXG4gIGxldCB0ZXJtaW5hdG9yID0gJydcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBzdHIubGVuZ3RoOyBpICs9IDEpIHtcbiAgICBjb25zdCBjaGFyID0gc3RyW2ldXG4gICAgaWYgKGNoYXIgPT09ICdcXHInIHx8IGNoYXIgPT09ICdcXG4nKSB7XG4gICAgICBjb25zdCBuZXh0Q2hhciA9IHN0cltpICsgMV1cbiAgICAgIHRlcm1pbmF0b3IgKz0gY2hhclxuICAgICAgLy8gRGV0ZWN0IFdpbmRvd3MgYW5kIE1hY2ludG9zaCBsaW5lIHRlcm1pbmF0b3JzLlxuICAgICAgaWYgKCh0ZXJtaW5hdG9yICsgbmV4dENoYXIpID09PSAnXFxyXFxuJyB8fCAodGVybWluYXRvciArIG5leHRDaGFyKSA9PT0gJ1xcblxccicpIHtcbiAgICAgICAgY2FsbGJhY2sobGluZSwgdGVybWluYXRvciArIG5leHRDaGFyKVxuICAgICAgICBsaW5lID0gJydcbiAgICAgICAgdGVybWluYXRvciA9ICcnXG4gICAgICAgIGkgKz0gMVxuICAgICAgLy8gRGV0ZWN0IHNpbmdsZS1jaGFyYWN0ZXIgdGVybWluYXRvcnMsIGxpa2UgTGludXggb3Igb3RoZXIgc3lzdGVtLlxuICAgICAgfSBlbHNlIGlmICh0ZXJtaW5hdG9yID09PSAnXFxuJyB8fCB0ZXJtaW5hdG9yID09PSAnXFxyJykge1xuICAgICAgICBjYWxsYmFjayhsaW5lLCB0ZXJtaW5hdG9yKVxuICAgICAgICBsaW5lID0gJydcbiAgICAgICAgdGVybWluYXRvciA9ICcnXG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGxpbmUgKz0gY2hhclxuICAgIH1cbiAgfVxuICAvLyBGbHVzaCB0aGUgbGluZSBhbmQgdGVybWluYXRvciB2YWx1ZXMgaWYgbmVjZXNzYXJ5OyBoYW5kbGUgZWRnZSBjYXNlcyB3aGVyZSBNSU1FIGlzIGdlbmVyYXRlZCB3aXRob3V0IGxhc3QgbGluZSB0ZXJtaW5hdG9yLlxuICBpZiAobGluZSAhPT0gJycgfHwgdGVybWluYXRvciAhPT0gJycpIHtcbiAgICBjYWxsYmFjayhsaW5lLCB0ZXJtaW5hdG9yKVxuICB9XG59XG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIHBhcnNlIChjaHVuaykge1xuICBjb25zdCByb290ID0gbmV3IE1pbWVOb2RlKG5ldyBOb2RlQ291bnRlcigpKVxuICBjb25zdCBzdHIgPSB0eXBlb2YgY2h1bmsgPT09ICdzdHJpbmcnID8gY2h1bmsgOiBTdHJpbmcuZnJvbUNoYXJDb2RlLmFwcGx5KG51bGwsIGNodW5rKVxuICBmb3JFYWNoTGluZShzdHIsIGZ1bmN0aW9uIChsaW5lLCB0ZXJtaW5hdG9yKSB7XG4gICAgcm9vdC53cml0ZUxpbmUobGluZSwgdGVybWluYXRvcilcbiAgfSlcbiAgcm9vdC5maW5hbGl6ZSgpXG4gIHJldHVybiByb290XG59XG5cbmV4cG9ydCBjbGFzcyBNaW1lTm9kZSB7XG4gIGNvbnN0cnVjdG9yIChub2RlQ291bnRlciA9IG5ldyBOb2RlQ291bnRlcigpKSB7XG4gICAgdGhpcy5ub2RlQ291bnRlciA9IG5vZGVDb3VudGVyXG4gICAgdGhpcy5ub2RlQ291bnRlci5idW1wKClcblxuICAgIHRoaXMuaGVhZGVyID0gW10gLy8gQW4gYXJyYXkgb2YgdW5mb2xkZWQgaGVhZGVyIGxpbmVzXG4gICAgdGhpcy5oZWFkZXJzID0ge30gLy8gQW4gb2JqZWN0IHRoYXQgaG9sZHMgaGVhZGVyIGtleT12YWx1ZSBwYWlyc1xuICAgIHRoaXMuYm9keXN0cnVjdHVyZSA9ICcnXG4gICAgdGhpcy5jaGlsZE5vZGVzID0gW10gLy8gSWYgdGhpcyBpcyBhIG11bHRpcGFydCBvciBtZXNzYWdlL3JmYzgyMiBtaW1lIHBhcnQsIHRoZSB2YWx1ZSB3aWxsIGJlIGNvbnZlcnRlZCB0byBhcnJheSBhbmQgaG9sZCBhbGwgY2hpbGQgbm9kZXMgZm9yIHRoaXMgbm9kZVxuICAgIHRoaXMucmF3ID0gJycgLy8gU3RvcmVzIHRoZSByYXcgY29udGVudCBvZiB0aGlzIG5vZGVcblxuICAgIHRoaXMuX3N0YXRlID0gJ0hFQURFUicgLy8gQ3VycmVudCBzdGF0ZSwgYWx3YXlzIHN0YXJ0cyBvdXQgd2l0aCBIRUFERVJcbiAgICB0aGlzLl9ib2R5QnVmZmVyID0gJycgLy8gQm9keSBidWZmZXJcbiAgICB0aGlzLl9saW5lQ291bnQgPSAwIC8vIExpbmUgY291bnRlciBib3IgdGhlIGJvZHkgcGFydFxuICAgIHRoaXMuX2N1cnJlbnRDaGlsZCA9IGZhbHNlIC8vIEFjdGl2ZSBjaGlsZCBub2RlIChpZiBhdmFpbGFibGUpXG4gICAgdGhpcy5fbGluZVJlbWFpbmRlciA9ICcnIC8vIFJlbWFpbmRlciBzdHJpbmcgd2hlbiBkZWFsaW5nIHdpdGggYmFzZTY0IGFuZCBxcCB2YWx1ZXNcbiAgICB0aGlzLl9pc011bHRpcGFydCA9IGZhbHNlIC8vIEluZGljYXRlcyBpZiB0aGlzIGlzIGEgbXVsdGlwYXJ0IG5vZGVcbiAgICB0aGlzLl9tdWx0aXBhcnRCb3VuZGFyeSA9IGZhbHNlIC8vIFN0b3JlcyBib3VuZGFyeSB2YWx1ZSBmb3IgY3VycmVudCBtdWx0aXBhcnQgbm9kZVxuICAgIHRoaXMuX2lzUmZjODIyID0gZmFsc2UgLy8gSW5kaWNhdGVzIGlmIHRoaXMgaXMgYSBtZXNzYWdlL3JmYzgyMiBub2RlXG4gIH1cblxuICB3cml0ZUxpbmUgKGxpbmUsIHRlcm1pbmF0b3IpIHtcbiAgICB0aGlzLnJhdyArPSBsaW5lICsgKHRlcm1pbmF0b3IgfHwgJ1xcbicpXG5cbiAgICBpZiAodGhpcy5fc3RhdGUgPT09ICdIRUFERVInKSB7XG4gICAgICB0aGlzLl9wcm9jZXNzSGVhZGVyTGluZShsaW5lKVxuICAgIH0gZWxzZSBpZiAodGhpcy5fc3RhdGUgPT09ICdCT0RZJykge1xuICAgICAgdGhpcy5fcHJvY2Vzc0JvZHlMaW5lKGxpbmUsIHRlcm1pbmF0b3IpXG4gICAgfVxuICB9XG5cbiAgZmluYWxpemUgKCkge1xuICAgIGlmICh0aGlzLl9pc1JmYzgyMikge1xuICAgICAgLy8gU29tZSBEU04ncyBsYWNrIGJvZHkgZGVzcGl0ZSByZmM4MjIgYW5kIGxhY2sgbmV3bGluZSB0byBpZGVudGlmeSBoZWFkIG9mIGhlYWRlcnMsIGNhcHR1cmUgYW5kIGZpeCBoZXJlXG4gICAgICBpZiAodGhpcy5fY3VycmVudENoaWxkLl9zdGF0ZSA9PT0gJ0hFQURFUicpIHtcbiAgICAgICAgdGhpcy5fY3VycmVudENoaWxkLndyaXRlTGluZSgnJylcbiAgICAgIH1cbiAgICAgIHRoaXMuX2N1cnJlbnRDaGlsZC5maW5hbGl6ZSgpXG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuX2VtaXRCb2R5KClcbiAgICB9XG5cbiAgICB0aGlzLmJvZHlzdHJ1Y3R1cmUgPSB0aGlzLmNoaWxkTm9kZXNcbiAgICAgIC5yZWR1Y2UoKGFnZywgY2hpbGQpID0+IGFnZyArICctLScgKyB0aGlzLl9tdWx0aXBhcnRCb3VuZGFyeSArICdcXG4nICsgY2hpbGQuYm9keXN0cnVjdHVyZSwgdGhpcy5oZWFkZXIuam9pbignXFxuJykgKyAnXFxuXFxuJykgK1xuICAgICAgKHRoaXMuX211bHRpcGFydEJvdW5kYXJ5ID8gJy0tJyArIHRoaXMuX211bHRpcGFydEJvdW5kYXJ5ICsgJy0tXFxuJyA6ICcnKVxuICB9XG5cbiAgX2RlY29kZUJvZHlCdWZmZXIgKCkge1xuICAgIHN3aXRjaCAodGhpcy5jb250ZW50VHJhbnNmZXJFbmNvZGluZy52YWx1ZSkge1xuICAgICAgY2FzZSAnYmFzZTY0JzpcbiAgICAgICAgdGhpcy5fYm9keUJ1ZmZlciA9IGJhc2U2NERlY29kZSh0aGlzLl9ib2R5QnVmZmVyLCB0aGlzLmNoYXJzZXQpXG4gICAgICAgIGJyZWFrXG4gICAgICBjYXNlICdxdW90ZWQtcHJpbnRhYmxlJzoge1xuICAgICAgICB0aGlzLl9ib2R5QnVmZmVyID0gdGhpcy5fYm9keUJ1ZmZlclxuICAgICAgICAgIC5yZXBsYWNlKC89KFxccj9cXG58JCkvZywgJycpXG4gICAgICAgICAgLnJlcGxhY2UoLz0oW2EtZjAtOV17Mn0pL2lnLCAobSwgY29kZSkgPT4gU3RyaW5nLmZyb21DaGFyQ29kZShwYXJzZUludChjb2RlLCAxNikpKVxuICAgICAgICBicmVha1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBQcm9jZXNzZXMgYSBsaW5lIGluIHRoZSBIRUFERVIgc3RhdGUuIEl0IHRoZSBsaW5lIGlzIGVtcHR5LCBjaGFuZ2Ugc3RhdGUgdG8gQk9EWVxuICAgKlxuICAgKiBAcGFyYW0ge1N0cmluZ30gbGluZSBFbnRpcmUgaW5wdXQgbGluZSBhcyAnYmluYXJ5JyBzdHJpbmdcbiAgICovXG4gIF9wcm9jZXNzSGVhZGVyTGluZSAobGluZSkge1xuICAgIGlmICghbGluZSkge1xuICAgICAgdGhpcy5fcGFyc2VIZWFkZXJzKClcbiAgICAgIHRoaXMuYm9keXN0cnVjdHVyZSArPSB0aGlzLmhlYWRlci5qb2luKCdcXG4nKSArICdcXG5cXG4nXG4gICAgICB0aGlzLl9zdGF0ZSA9ICdCT0RZJ1xuICAgICAgcmV0dXJuXG4gICAgfVxuXG4gICAgaWYgKGxpbmUubWF0Y2goL15cXHMvKSAmJiB0aGlzLmhlYWRlci5sZW5ndGgpIHtcbiAgICAgIHRoaXMuaGVhZGVyW3RoaXMuaGVhZGVyLmxlbmd0aCAtIDFdICs9ICdcXG4nICsgbGluZVxuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLmhlYWRlci5wdXNoKGxpbmUpXG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIEpvaW5zIGZvbGRlZCBoZWFkZXIgbGluZXMgYW5kIGNhbGxzIENvbnRlbnQtVHlwZSBhbmQgVHJhbnNmZXItRW5jb2RpbmcgcHJvY2Vzc29yc1xuICAgKi9cbiAgX3BhcnNlSGVhZGVycyAoKSB7XG4gICAgZm9yIChsZXQgaGFzQmluYXJ5ID0gZmFsc2UsIGkgPSAwLCBsZW4gPSB0aGlzLmhlYWRlci5sZW5ndGg7IGkgPCBsZW47IGkrKykge1xuICAgICAgbGV0IHZhbHVlID0gdGhpcy5oZWFkZXJbaV0uc3BsaXQoJzonKVxuICAgICAgY29uc3Qga2V5ID0gKHZhbHVlLnNoaWZ0KCkgfHwgJycpLnRyaW0oKS50b0xvd2VyQ2FzZSgpXG4gICAgICB2YWx1ZSA9ICh2YWx1ZS5qb2luKCc6JykgfHwgJycpLnJlcGxhY2UoL1xcbi9nLCAnJykudHJpbSgpXG5cbiAgICAgIGlmICh2YWx1ZS5tYXRjaCgvW1xcdTAwODAtXFx1RkZGRl0vKSkge1xuICAgICAgICBpZiAoIXRoaXMuY2hhcnNldCkge1xuICAgICAgICAgIGhhc0JpbmFyeSA9IHRydWVcbiAgICAgICAgfVxuICAgICAgICAvLyB1c2UgZGVmYXVsdCBjaGFyc2V0IGF0IGZpcnN0IGFuZCBpZiB0aGUgYWN0dWFsIGNoYXJzZXQgaXMgcmVzb2x2ZWQsIHRoZSBjb252ZXJzaW9uIGlzIHJlLXJ1blxuICAgICAgICB2YWx1ZSA9IGRlY29kZShjb252ZXJ0KHN0cjJhcnIodmFsdWUpLCB0aGlzLmNoYXJzZXQgfHwgJ2lzby04ODU5LTEnKSlcbiAgICAgIH1cblxuICAgICAgdGhpcy5oZWFkZXJzW2tleV0gPSAodGhpcy5oZWFkZXJzW2tleV0gfHwgW10pLmNvbmNhdChbdGhpcy5fcGFyc2VIZWFkZXJWYWx1ZShrZXksIHZhbHVlKV0pXG5cbiAgICAgIGlmICghdGhpcy5jaGFyc2V0ICYmIGtleSA9PT0gJ2NvbnRlbnQtdHlwZScpIHtcbiAgICAgICAgdGhpcy5jaGFyc2V0ID0gdGhpcy5oZWFkZXJzW2tleV1bdGhpcy5oZWFkZXJzW2tleV0ubGVuZ3RoIC0gMV0ucGFyYW1zLmNoYXJzZXRcbiAgICAgIH1cblxuICAgICAgaWYgKGhhc0JpbmFyeSAmJiB0aGlzLmNoYXJzZXQpIHtcbiAgICAgICAgLy8gcmVzZXQgdmFsdWVzIGFuZCBzdGFydCBvdmVyIG9uY2UgY2hhcnNldCBoYXMgYmVlbiByZXNvbHZlZCBhbmQgOGJpdCBjb250ZW50IGhhcyBiZWVuIGZvdW5kXG4gICAgICAgIGhhc0JpbmFyeSA9IGZhbHNlXG4gICAgICAgIHRoaXMuaGVhZGVycyA9IHt9XG4gICAgICAgIGkgPSAtMSAvLyBuZXh0IGl0ZXJhdGlvbiBoYXMgaSA9PSAwXG4gICAgICB9XG4gICAgfVxuXG4gICAgdGhpcy5mZXRjaENvbnRlbnRUeXBlKClcbiAgICB0aGlzLl9wcm9jZXNzQ29udGVudFRyYW5zZmVyRW5jb2RpbmcoKVxuICB9XG5cbiAgLyoqXG4gICAqIFBhcnNlcyBzaW5nbGUgaGVhZGVyIHZhbHVlXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBrZXkgSGVhZGVyIGtleVxuICAgKiBAcGFyYW0ge1N0cmluZ30gdmFsdWUgVmFsdWUgZm9yIHRoZSBrZXlcbiAgICogQHJldHVybiB7T2JqZWN0fSBwYXJzZWQgaGVhZGVyXG4gICAqL1xuICBfcGFyc2VIZWFkZXJWYWx1ZSAoa2V5LCB2YWx1ZSkge1xuICAgIGxldCBwYXJzZWRWYWx1ZVxuICAgIGxldCBpc0FkZHJlc3MgPSBmYWxzZVxuXG4gICAgc3dpdGNoIChrZXkpIHtcbiAgICAgIGNhc2UgJ2NvbnRlbnQtdHlwZSc6XG4gICAgICBjYXNlICdjb250ZW50LXRyYW5zZmVyLWVuY29kaW5nJzpcbiAgICAgIGNhc2UgJ2NvbnRlbnQtZGlzcG9zaXRpb24nOlxuICAgICAgY2FzZSAnZGtpbS1zaWduYXR1cmUnOlxuICAgICAgICBwYXJzZWRWYWx1ZSA9IHBhcnNlSGVhZGVyVmFsdWUodmFsdWUpXG4gICAgICAgIGJyZWFrXG4gICAgICBjYXNlICdmcm9tJzpcbiAgICAgIGNhc2UgJ3NlbmRlcic6XG4gICAgICBjYXNlICd0byc6XG4gICAgICBjYXNlICdyZXBseS10byc6XG4gICAgICBjYXNlICdjYyc6XG4gICAgICBjYXNlICdiY2MnOlxuICAgICAgY2FzZSAnYWJ1c2UtcmVwb3J0cy10byc6XG4gICAgICBjYXNlICdlcnJvcnMtdG8nOlxuICAgICAgY2FzZSAncmV0dXJuLXBhdGgnOlxuICAgICAgY2FzZSAnZGVsaXZlcmVkLXRvJzpcbiAgICAgICAgaXNBZGRyZXNzID0gdHJ1ZVxuICAgICAgICBwYXJzZWRWYWx1ZSA9IHtcbiAgICAgICAgICB2YWx1ZTogW10uY29uY2F0KHBhcnNlQWRkcmVzcyh2YWx1ZSkgfHwgW10pXG4gICAgICAgIH1cbiAgICAgICAgYnJlYWtcbiAgICAgIGNhc2UgJ2RhdGUnOlxuICAgICAgICBwYXJzZWRWYWx1ZSA9IHtcbiAgICAgICAgICB2YWx1ZTogdGhpcy5fcGFyc2VEYXRlKHZhbHVlKVxuICAgICAgICB9XG4gICAgICAgIGJyZWFrXG4gICAgICBkZWZhdWx0OlxuICAgICAgICBwYXJzZWRWYWx1ZSA9IHtcbiAgICAgICAgICB2YWx1ZTogdmFsdWVcbiAgICAgICAgfVxuICAgIH1cbiAgICBwYXJzZWRWYWx1ZS5pbml0aWFsID0gdmFsdWVcblxuICAgIHRoaXMuX2RlY29kZUhlYWRlckNoYXJzZXQocGFyc2VkVmFsdWUsIHsgaXNBZGRyZXNzIH0pXG5cbiAgICByZXR1cm4gcGFyc2VkVmFsdWVcbiAgfVxuXG4gIC8qKlxuICAgKiBDaGVja3MgaWYgYSBkYXRlIHN0cmluZyBjYW4gYmUgcGFyc2VkLiBGYWxscyBiYWNrIHJlcGxhY2luZyB0aW1lem9uZVxuICAgKiBhYmJyZXZhdGlvbnMgd2l0aCB0aW1lem9uZSB2YWx1ZXMuIEJvZ3VzIHRpbWV6b25lcyBkZWZhdWx0IHRvIFVUQy5cbiAgICpcbiAgICogQHBhcmFtIHtTdHJpbmd9IHN0ciBEYXRlIGhlYWRlclxuICAgKiBAcmV0dXJucyB7U3RyaW5nfSBVVEMgZGF0ZSBzdHJpbmcgaWYgcGFyc2luZyBzdWNjZWVkZWQsIG90aGVyd2lzZSByZXR1cm5zIGlucHV0IHZhbHVlXG4gICAqL1xuICBfcGFyc2VEYXRlIChzdHIgPSAnJykge1xuICAgIGNvbnN0IGRhdGUgPSBuZXcgRGF0ZShzdHIudHJpbSgpLnJlcGxhY2UoL1xcYlthLXpdKyQvaSwgdHogPT4gdGltZXpvbmVbdHoudG9VcHBlckNhc2UoKV0gfHwgJyswMDAwJykpXG4gICAgcmV0dXJuIChkYXRlLnRvU3RyaW5nKCkgIT09ICdJbnZhbGlkIERhdGUnKSA/IGRhdGUudG9VVENTdHJpbmcoKS5yZXBsYWNlKC9HTVQvLCAnKzAwMDAnKSA6IHN0clxuICB9XG5cbiAgX2RlY29kZUhlYWRlckNoYXJzZXQgKHBhcnNlZCwgeyBpc0FkZHJlc3MgfSA9IHt9KSB7XG4gICAgLy8gZGVjb2RlIGRlZmF1bHQgdmFsdWVcbiAgICBpZiAodHlwZW9mIHBhcnNlZC52YWx1ZSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIHBhcnNlZC52YWx1ZSA9IG1pbWVXb3Jkc0RlY29kZShwYXJzZWQudmFsdWUpXG4gICAgfVxuXG4gICAgLy8gZGVjb2RlIHBvc3NpYmxlIHBhcmFtc1xuICAgIE9iamVjdC5rZXlzKHBhcnNlZC5wYXJhbXMgfHwge30pLmZvckVhY2goZnVuY3Rpb24gKGtleSkge1xuICAgICAgaWYgKHR5cGVvZiBwYXJzZWQucGFyYW1zW2tleV0gPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHBhcnNlZC5wYXJhbXNba2V5XSA9IG1pbWVXb3Jkc0RlY29kZShwYXJzZWQucGFyYW1zW2tleV0pXG4gICAgICB9XG4gICAgfSlcblxuICAgIC8vIGRlY29kZSBhZGRyZXNzZXNcbiAgICBpZiAoaXNBZGRyZXNzICYmIEFycmF5LmlzQXJyYXkocGFyc2VkLnZhbHVlKSkge1xuICAgICAgcGFyc2VkLnZhbHVlLmZvckVhY2goYWRkciA9PiB7XG4gICAgICAgIGlmIChhZGRyLm5hbWUpIHtcbiAgICAgICAgICBhZGRyLm5hbWUgPSBtaW1lV29yZHNEZWNvZGUoYWRkci5uYW1lKVxuICAgICAgICAgIGlmIChBcnJheS5pc0FycmF5KGFkZHIuZ3JvdXApKSB7XG4gICAgICAgICAgICB0aGlzLl9kZWNvZGVIZWFkZXJDaGFyc2V0KHsgdmFsdWU6IGFkZHIuZ3JvdXAgfSwgeyBpc0FkZHJlc3M6IHRydWUgfSlcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH0pXG4gICAgfVxuXG4gICAgcmV0dXJuIHBhcnNlZFxuICB9XG5cbiAgLyoqXG4gICAqIFBhcnNlcyBDb250ZW50LVR5cGUgdmFsdWUgYW5kIHNlbGVjdHMgZm9sbG93aW5nIGFjdGlvbnMuXG4gICAqL1xuICBmZXRjaENvbnRlbnRUeXBlICgpIHtcbiAgICBjb25zdCBkZWZhdWx0VmFsdWUgPSBwYXJzZUhlYWRlclZhbHVlKCd0ZXh0L3BsYWluJylcbiAgICB0aGlzLmNvbnRlbnRUeXBlID0gcGF0aE9yKGRlZmF1bHRWYWx1ZSwgWydoZWFkZXJzJywgJ2NvbnRlbnQtdHlwZScsICcwJ10pKHRoaXMpXG4gICAgdGhpcy5jb250ZW50VHlwZS52YWx1ZSA9ICh0aGlzLmNvbnRlbnRUeXBlLnZhbHVlIHx8ICcnKS50b0xvd2VyQ2FzZSgpLnRyaW0oKVxuICAgIHRoaXMuY29udGVudFR5cGUudHlwZSA9ICh0aGlzLmNvbnRlbnRUeXBlLnZhbHVlLnNwbGl0KCcvJykuc2hpZnQoKSB8fCAndGV4dCcpXG5cbiAgICBpZiAodGhpcy5jb250ZW50VHlwZS5wYXJhbXMgJiYgdGhpcy5jb250ZW50VHlwZS5wYXJhbXMuY2hhcnNldCAmJiAhdGhpcy5jaGFyc2V0KSB7XG4gICAgICB0aGlzLmNoYXJzZXQgPSB0aGlzLmNvbnRlbnRUeXBlLnBhcmFtcy5jaGFyc2V0XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuY29udGVudFR5cGUudHlwZSA9PT0gJ211bHRpcGFydCcgJiYgdGhpcy5jb250ZW50VHlwZS5wYXJhbXMuYm91bmRhcnkpIHtcbiAgICAgIHRoaXMuY2hpbGROb2RlcyA9IFtdXG4gICAgICB0aGlzLl9pc011bHRpcGFydCA9ICh0aGlzLmNvbnRlbnRUeXBlLnZhbHVlLnNwbGl0KCcvJykucG9wKCkgfHwgJ21peGVkJylcbiAgICAgIHRoaXMuX211bHRpcGFydEJvdW5kYXJ5ID0gdGhpcy5jb250ZW50VHlwZS5wYXJhbXMuYm91bmRhcnlcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBGb3IgYXR0YWNobWVudCAoaW5saW5lL3JlZ3VsYXIpIGlmIGNoYXJzZXQgaXMgbm90IGRlZmluZWQgYW5kIGF0dGFjaG1lbnQgaXMgbm9uLXRleHQvKixcbiAgICAgKiB0aGVuIGRlZmF1bHQgY2hhcnNldCB0byBiaW5hcnkuXG4gICAgICogUmVmZXIgdG8gaXNzdWU6IGh0dHBzOi8vZ2l0aHViLmNvbS9lbWFpbGpzL2VtYWlsanMtbWltZS1wYXJzZXIvaXNzdWVzLzE4XG4gICAgICovXG4gICAgY29uc3QgZGVmYXVsdENvbnRlbnREaXNwb3NpdGlvblZhbHVlID0gcGFyc2VIZWFkZXJWYWx1ZSgnJylcbiAgICBjb25zdCBjb250ZW50RGlzcG9zaXRpb24gPSBwYXRoT3IoZGVmYXVsdENvbnRlbnREaXNwb3NpdGlvblZhbHVlLCBbJ2hlYWRlcnMnLCAnY29udGVudC1kaXNwb3NpdGlvbicsICcwJ10pKHRoaXMpXG4gICAgY29uc3QgaXNBdHRhY2htZW50ID0gKGNvbnRlbnREaXNwb3NpdGlvbi52YWx1ZSB8fCAnJykudG9Mb3dlckNhc2UoKS50cmltKCkgPT09ICdhdHRhY2htZW50J1xuICAgIGNvbnN0IGlzSW5saW5lQXR0YWNobWVudCA9IChjb250ZW50RGlzcG9zaXRpb24udmFsdWUgfHwgJycpLnRvTG93ZXJDYXNlKCkudHJpbSgpID09PSAnaW5saW5lJ1xuICAgIGlmICgoaXNBdHRhY2htZW50IHx8IGlzSW5saW5lQXR0YWNobWVudCkgJiYgdGhpcy5jb250ZW50VHlwZS50eXBlICE9PSAndGV4dCcgJiYgIXRoaXMuY2hhcnNldCkge1xuICAgICAgdGhpcy5jaGFyc2V0ID0gJ2JpbmFyeSdcbiAgICB9XG5cbiAgICBpZiAodGhpcy5jb250ZW50VHlwZS52YWx1ZSA9PT0gJ21lc3NhZ2UvcmZjODIyJyAmJiAhaXNBdHRhY2htZW50KSB7XG4gICAgICAvKipcbiAgICAgICAqIFBhcnNlIG1lc3NhZ2UvcmZjODIyIG9ubHkgaWYgdGhlIG1pbWUgcGFydCBpcyBub3QgbWFya2VkIHdpdGggY29udGVudC1kaXNwb3NpdGlvbjogYXR0YWNobWVudCxcbiAgICAgICAqIG90aGVyd2lzZSB0cmVhdCBpdCBsaWtlIGEgcmVndWxhciBhdHRhY2htZW50XG4gICAgICAgKi9cbiAgICAgIHRoaXMuX2N1cnJlbnRDaGlsZCA9IG5ldyBNaW1lTm9kZSh0aGlzLm5vZGVDb3VudGVyKVxuICAgICAgdGhpcy5jaGlsZE5vZGVzID0gW3RoaXMuX2N1cnJlbnRDaGlsZF1cbiAgICAgIHRoaXMuX2lzUmZjODIyID0gdHJ1ZVxuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBQYXJzZXMgQ29udGVudC1UcmFuc2Zlci1FbmNvZGluZyB2YWx1ZSB0byBzZWUgaWYgdGhlIGJvZHkgbmVlZHMgdG8gYmUgY29udmVydGVkXG4gICAqIGJlZm9yZSBpdCBjYW4gYmUgZW1pdHRlZFxuICAgKi9cbiAgX3Byb2Nlc3NDb250ZW50VHJhbnNmZXJFbmNvZGluZyAoKSB7XG4gICAgY29uc3QgZGVmYXVsdFZhbHVlID0gcGFyc2VIZWFkZXJWYWx1ZSgnN2JpdCcpXG4gICAgdGhpcy5jb250ZW50VHJhbnNmZXJFbmNvZGluZyA9IHBhdGhPcihkZWZhdWx0VmFsdWUsIFsnaGVhZGVycycsICdjb250ZW50LXRyYW5zZmVyLWVuY29kaW5nJywgJzAnXSkodGhpcylcbiAgICB0aGlzLmNvbnRlbnRUcmFuc2ZlckVuY29kaW5nLnZhbHVlID0gcGF0aE9yKCcnLCBbJ2NvbnRlbnRUcmFuc2ZlckVuY29kaW5nJywgJ3ZhbHVlJ10pKHRoaXMpLnRvTG93ZXJDYXNlKCkudHJpbSgpXG4gIH1cblxuICAvKipcbiAgICogUHJvY2Vzc2VzIGEgbGluZSBpbiB0aGUgQk9EWSBzdGF0ZS4gSWYgdGhpcyBpcyBhIG11bHRpcGFydCBvciByZmM4MjIgbm9kZSxcbiAgICogcGFzc2VzIGxpbmUgdmFsdWUgdG8gY2hpbGQgbm9kZXMuXG4gICAqXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBsaW5lIEVudGlyZSBpbnB1dCBsaW5lIGFzICdiaW5hcnknIHN0cmluZ1xuICAgKiBAcGFyYW0ge1N0cmluZ30gdGVybWluYXRvciBUaGUgbGluZSB0ZXJtaW5hdG9yIGRldGVjdGVkIGJ5IHBhcnNlclxuICAgKi9cbiAgX3Byb2Nlc3NCb2R5TGluZSAobGluZSwgdGVybWluYXRvcikge1xuICAgIGlmICh0aGlzLl9pc011bHRpcGFydCkge1xuICAgICAgaWYgKGxpbmUgPT09ICctLScgKyB0aGlzLl9tdWx0aXBhcnRCb3VuZGFyeSkge1xuICAgICAgICB0aGlzLmJvZHlzdHJ1Y3R1cmUgKz0gbGluZSArICdcXG4nXG4gICAgICAgIGlmICh0aGlzLl9jdXJyZW50Q2hpbGQpIHtcbiAgICAgICAgICB0aGlzLl9jdXJyZW50Q2hpbGQuZmluYWxpemUoKVxuICAgICAgICB9XG4gICAgICAgIHRoaXMuX2N1cnJlbnRDaGlsZCA9IG5ldyBNaW1lTm9kZSh0aGlzLm5vZGVDb3VudGVyKVxuICAgICAgICB0aGlzLmNoaWxkTm9kZXMucHVzaCh0aGlzLl9jdXJyZW50Q2hpbGQpXG4gICAgICB9IGVsc2UgaWYgKGxpbmUgPT09ICctLScgKyB0aGlzLl9tdWx0aXBhcnRCb3VuZGFyeSArICctLScpIHtcbiAgICAgICAgdGhpcy5ib2R5c3RydWN0dXJlICs9IGxpbmUgKyAnXFxuJ1xuICAgICAgICBpZiAodGhpcy5fY3VycmVudENoaWxkKSB7XG4gICAgICAgICAgdGhpcy5fY3VycmVudENoaWxkLmZpbmFsaXplKClcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9jdXJyZW50Q2hpbGQgPSBmYWxzZVxuICAgICAgfSBlbHNlIGlmICh0aGlzLl9jdXJyZW50Q2hpbGQpIHtcbiAgICAgICAgdGhpcy5fY3VycmVudENoaWxkLndyaXRlTGluZShsaW5lLCB0ZXJtaW5hdG9yKVxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gSWdub3JlIG11bHRpcGFydCBwcmVhbWJsZVxuICAgICAgfVxuICAgIH0gZWxzZSBpZiAodGhpcy5faXNSZmM4MjIpIHtcbiAgICAgIHRoaXMuX2N1cnJlbnRDaGlsZC53cml0ZUxpbmUobGluZSwgdGVybWluYXRvcilcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5fbGluZUNvdW50KytcblxuICAgICAgc3dpdGNoICh0aGlzLmNvbnRlbnRUcmFuc2ZlckVuY29kaW5nLnZhbHVlKSB7XG4gICAgICAgIGNhc2UgJ2Jhc2U2NCc6XG4gICAgICAgICAgdGhpcy5fYm9keUJ1ZmZlciArPSBsaW5lICsgdGVybWluYXRvclxuICAgICAgICAgIGJyZWFrXG4gICAgICAgIGNhc2UgJ3F1b3RlZC1wcmludGFibGUnOiB7XG4gICAgICAgICAgbGV0IGN1ckxpbmUgPSB0aGlzLl9saW5lUmVtYWluZGVyICsgbGluZSArIHRlcm1pbmF0b3JcbiAgICAgICAgICBjb25zdCBtYXRjaCA9IGN1ckxpbmUubWF0Y2goLz1bYS1mMC05XXswLDF9JC9pKVxuICAgICAgICAgIGlmIChtYXRjaCkge1xuICAgICAgICAgICAgdGhpcy5fbGluZVJlbWFpbmRlciA9IG1hdGNoWzBdXG4gICAgICAgICAgICBjdXJMaW5lID0gY3VyTGluZS5zdWJzdHIoMCwgY3VyTGluZS5sZW5ndGggLSB0aGlzLl9saW5lUmVtYWluZGVyLmxlbmd0aClcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhpcy5fbGluZVJlbWFpbmRlciA9ICcnXG4gICAgICAgICAgfVxuICAgICAgICAgIHRoaXMuX2JvZHlCdWZmZXIgKz0gY3VyTGluZVxuICAgICAgICAgIGJyZWFrXG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnN2JpdCc6XG4gICAgICAgIGNhc2UgJzhiaXQnOlxuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgIHRoaXMuX2JvZHlCdWZmZXIgKz0gbGluZSArIHRlcm1pbmF0b3JcbiAgICAgICAgICBicmVha1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBFbWl0cyBhIGNodW5rIG9mIHRoZSBib2R5XG4gICovXG4gIF9lbWl0Qm9keSAoKSB7XG4gICAgdGhpcy5fZGVjb2RlQm9keUJ1ZmZlcigpXG4gICAgaWYgKHRoaXMuX2lzTXVsdGlwYXJ0IHx8ICF0aGlzLl9ib2R5QnVmZmVyKSB7XG4gICAgICByZXR1cm5cbiAgICB9XG5cbiAgICB0aGlzLl9wcm9jZXNzRmxvd2VkVGV4dCgpXG4gICAgdGhpcy5jb250ZW50ID0gc3RyMmFycih0aGlzLl9ib2R5QnVmZmVyKVxuICAgIHRoaXMuX3Byb2Nlc3NIdG1sVGV4dCgpXG4gICAgdGhpcy5fYm9keUJ1ZmZlciA9ICcnXG4gIH1cblxuICBfcHJvY2Vzc0Zsb3dlZFRleHQgKCkge1xuICAgIGNvbnN0IGlzVGV4dCA9IC9edGV4dFxcLyhwbGFpbnxodG1sKSQvaS50ZXN0KHRoaXMuY29udGVudFR5cGUudmFsdWUpXG4gICAgY29uc3QgaXNGbG93ZWQgPSAvXmZsb3dlZCQvaS50ZXN0KHBhdGhPcignJywgWydjb250ZW50VHlwZScsICdwYXJhbXMnLCAnZm9ybWF0J10pKHRoaXMpKVxuICAgIGlmICghaXNUZXh0IHx8ICFpc0Zsb3dlZCkgcmV0dXJuXG5cbiAgICBjb25zdCBkZWxTcCA9IC9eeWVzJC9pLnRlc3QodGhpcy5jb250ZW50VHlwZS5wYXJhbXMuZGVsc3ApXG4gICAgbGV0IGJvZHlCdWZmZXIgPSAnJ1xuXG4gICAgZm9yRWFjaExpbmUodGhpcy5fYm9keUJ1ZmZlciwgZnVuY3Rpb24gKGxpbmUsIHRlcm1pbmF0b3IpIHtcbiAgICAgIC8vIHJlbW92ZSBzb2Z0IGxpbmVicmVha3MgYWZ0ZXIgc3BhY2Ugc3ltYm9scy5cbiAgICAgIC8vIGRlbHNwIGFkZHMgc3BhY2VzIHRvIHRleHQgdG8gYmUgYWJsZSB0byBmb2xkIGl0LlxuICAgICAgLy8gdGhlc2Ugc3BhY2VzIGNhbiBiZSByZW1vdmVkIG9uY2UgdGhlIHRleHQgaXMgdW5mb2xkZWRcbiAgICAgIGNvbnN0IGVuZHNXaXRoU3BhY2UgPSAvICQvLnRlc3QobGluZSlcbiAgICAgIGNvbnN0IGlzQm91bmRhcnkgPSAvKF58XFxuKS0tICQvLnRlc3QobGluZSlcblxuICAgICAgYm9keUJ1ZmZlciArPSAoZGVsU3AgPyBsaW5lLnJlcGxhY2UoL1sgXSskLywgJycpIDogbGluZSkgKyAoKGVuZHNXaXRoU3BhY2UgJiYgIWlzQm91bmRhcnkpID8gJycgOiB0ZXJtaW5hdG9yKVxuICAgIH0pXG5cbiAgICB0aGlzLl9ib2R5QnVmZmVyID0gYm9keUJ1ZmZlci5yZXBsYWNlKC9eIC9nbSwgJycpIC8vIHJlbW92ZSB3aGl0ZXNwYWNlIHN0dWZmaW5nIGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzM2NzYjc2VjdGlvbi00LjRcbiAgfVxuXG4gIF9wcm9jZXNzSHRtbFRleHQgKCkge1xuICAgIGNvbnN0IGNvbnRlbnREaXNwb3NpdGlvbiA9ICh0aGlzLmhlYWRlcnNbJ2NvbnRlbnQtZGlzcG9zaXRpb24nXSAmJiB0aGlzLmhlYWRlcnNbJ2NvbnRlbnQtZGlzcG9zaXRpb24nXVswXSkgfHwgcGFyc2VIZWFkZXJWYWx1ZSgnJylcbiAgICBjb25zdCBpc0h0bWwgPSAvXnRleHRcXC8ocGxhaW58aHRtbCkkL2kudGVzdCh0aGlzLmNvbnRlbnRUeXBlLnZhbHVlKVxuICAgIGNvbnN0IGlzQXR0YWNobWVudCA9IC9eYXR0YWNobWVudCQvaS50ZXN0KGNvbnRlbnREaXNwb3NpdGlvbi52YWx1ZSlcbiAgICBpZiAoaXNIdG1sICYmICFpc0F0dGFjaG1lbnQpIHtcbiAgICAgIGlmICghdGhpcy5jaGFyc2V0ICYmIC9edGV4dFxcL2h0bWwkL2kudGVzdCh0aGlzLmNvbnRlbnRUeXBlLnZhbHVlKSkge1xuICAgICAgICB0aGlzLmNoYXJzZXQgPSB0aGlzLmRldGVjdEhUTUxDaGFyc2V0KHRoaXMuX2JvZHlCdWZmZXIpXG4gICAgICB9XG5cbiAgICAgIC8vIGRlY29kZSBcImJpbmFyeVwiIHN0cmluZyB0byBhbiB1bmljb2RlIHN0cmluZ1xuICAgICAgaWYgKCEvXnV0ZlstX10/OCQvaS50ZXN0KHRoaXMuY2hhcnNldCkpIHtcbiAgICAgICAgdGhpcy5jb250ZW50ID0gY29udmVydChzdHIyYXJyKHRoaXMuX2JvZHlCdWZmZXIpLCB0aGlzLmNoYXJzZXQgfHwgJ2lzby04ODU5LTEnKVxuICAgICAgfSBlbHNlIGlmICh0aGlzLmNvbnRlbnRUcmFuc2ZlckVuY29kaW5nLnZhbHVlID09PSAnYmFzZTY0Jykge1xuICAgICAgICB0aGlzLmNvbnRlbnQgPSB1dGY4U3RyMmFycih0aGlzLl9ib2R5QnVmZmVyKVxuICAgICAgfVxuXG4gICAgICAvLyBvdmVycmlkZSBjaGFyc2V0IGZvciB0ZXh0IG5vZGVzXG4gICAgICB0aGlzLmNoYXJzZXQgPSB0aGlzLmNvbnRlbnRUeXBlLnBhcmFtcy5jaGFyc2V0ID0gJ3V0Zi04J1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBEZXRlY3QgY2hhcnNldCBmcm9tIGEgaHRtbCBmaWxlXG4gICAqXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBodG1sIElucHV0IEhUTUxcbiAgICogQHJldHVybnMge1N0cmluZ30gQ2hhcnNldCBpZiBmb3VuZCBvciB1bmRlZmluZWRcbiAgICovXG4gIGRldGVjdEhUTUxDaGFyc2V0IChodG1sKSB7XG4gICAgbGV0IGNoYXJzZXQsIGlucHV0XG5cbiAgICBodG1sID0gaHRtbC5yZXBsYWNlKC9cXHI/XFxufFxcci9nLCAnICcpXG4gICAgbGV0IG1ldGEgPSBodG1sLm1hdGNoKC88bWV0YVxccytodHRwLWVxdWl2PVtcIidcXHNdKmNvbnRlbnQtdHlwZVtePl0qPz4vaSlcbiAgICBpZiAobWV0YSkge1xuICAgICAgaW5wdXQgPSBtZXRhWzBdXG4gICAgfVxuXG4gICAgaWYgKGlucHV0KSB7XG4gICAgICBjaGFyc2V0ID0gaW5wdXQubWF0Y2goL2NoYXJzZXRcXHM/PVxccz8oW2EtekEtWlxcLV86MC05XSopOz8vKVxuICAgICAgaWYgKGNoYXJzZXQpIHtcbiAgICAgICAgY2hhcnNldCA9IChjaGFyc2V0WzFdIHx8ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKVxuICAgICAgfVxuICAgIH1cblxuICAgIG1ldGEgPSBodG1sLm1hdGNoKC88bWV0YVxccytjaGFyc2V0PVtcIidcXHNdKihbXlwiJzw+L1xcc10rKS9pKVxuICAgIGlmICghY2hhcnNldCAmJiBtZXRhKSB7XG4gICAgICBjaGFyc2V0ID0gKG1ldGFbMV0gfHwgJycpLnRyaW0oKS50b0xvd2VyQ2FzZSgpXG4gICAgfVxuXG4gICAgcmV0dXJuIGNoYXJzZXRcbiAgfVxufVxuXG5jb25zdCBzdHIyYXJyID0gc3RyID0+IG5ldyBVaW50OEFycmF5KHN0ci5zcGxpdCgnJykubWFwKGNoYXIgPT4gY2hhci5jaGFyQ29kZUF0KDApKSlcbmNvbnN0IHV0ZjhTdHIyYXJyID0gc3RyID0+IG5ldyBUZXh0RW5jb2RlcigndXRmLTgnKS5lbmNvZGUoc3RyKVxuIl19