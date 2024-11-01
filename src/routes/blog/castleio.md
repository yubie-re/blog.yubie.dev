---
title: Castle.io - A reversal of a commercial antibot solution
date: '2024-10-26'
author: 'yubie-re'
description: "This blog post explores the inner workings of castle.io's, and how I managed to emulate their behavior to generate and decode a X-Castle-Request-Token"
tags: "castle,castle.io,yubie,yubie.dev,blog.yubie.dev,castle.js,npm,selenium,sequentum,x-castle-request-token"
---
**Castle.io** is a Software-as-a-Service (SaaS) platform designed to help businesses combat spam, fraud, and malicious behavior online. By leveraging browser fingerprinting, Castle.io monitors, tracks, and analyzes user interactions, making it easier to distinguish between real users and automated bots. Websites using Castle.io append a `X-Castle-Request-Token` header, a Base64-encoded string containing fingerprint data about the user's device and browser. This blog post explores the inner workings of this token: what data is being transmitted, the obfuscation techniques used, and how I managed to emulate their behavior to generate and decode any `X-Castle-Request-Token` header.

## String deobfuscation

To begin the analysis, you can download the latest release from Castle.io’s [npm page](https://www.npmjs.com/package/@castleio/castle-js). I focused on version **2.4.1**, which, despite being somewhat outdated, retains the core functionality. The main code of interest is found in `castle.browser.js`, a minified JavaScript file with some obfuscated data blobs, as shown below.

![Obfuscated data blob](/images/obfuscation_code.png)

The file contains two data blobs at the top, which are accessed by two functions: `H(n)` for the first blob and `w(n)` for the second. Upon further examination, function `i(n)` implements **LZW decompression**, while `e(n,t)` is a **Caesar cipher**. With this knowledge, a simple script can replace the calls to `w` and `H` with their decoded strings, clearing up most of the obfuscation.

## Structure of the Token

The `X-Castle-Request-Token` contains three distinct parts:
1. **Basic browser fingerprint data**
2. **Advanced fingerprinting and WebDriver detection data**
3. **Input events and timing data**

```js
partOneLengthEncoded = packBitsToHexByte(0, storage1Values.length);
partTwoLengthEncoded = packBitsToHexByte(4, storage2Values.length);
fpData =
    partOneLengthEncoded +
    storage1Values.join("") +
    partTwoLengthEncoded +
    storage2Values.join("") +
    eventData.join("") +
    HexFF;
```

## Decoding the token: Part 1

The first part seems to come from an array of values I labeled as `storage1Values`. This is essentially an array of hex strings which have a specific type of encoding. The first byte is always fingerprint value index and serialization type, and the rest of the data depends on what type of value it is. Here is an example of how these are inserted:

![alt text](/images/fp_example.png)

They seem to define a constant for each type of fingerprint value. These are what I labeled each one for the first part:
```js
FP_PlatformEnum = 0,
FP_VendorEnum = 1,
FP_Language = 2,
FP_DeviceMemory = 3,
FP_ScreenDims = 4,
FP_ScreenDepth = 5,
FP_HardwareConcurrency = 6,
FP_ScreenPixelRatio = 7,
FP_TimezoneVsDst = 8,
FP_MimeTypesHash = 9,
FP_PluginsHash = 10,
FP_BrowserFeaturesBitfield = 11,
FP_UserAgent = 12,
FP_FontRenderHash = 13,
FP_MediaInputAvailableBitfield = 14,
FP_DoNotTrackPreference = 15,
FP_JavaEnabled = 16,
FP_ProductSubEnum = 17,
FP_CircleRenderHash = 18,
FP_GraphicsCard = 19,
FP_EpochLocaleStr = 20,
FP_WebDriverDetectionFlags = 21,
FP_Eval_ToString_Length = 22,
FP_NavigatorBuildID = 23,
FP_MaxRecursionLimit = 24,
FP_MaxRecursionLimitErrorMessageEnum = 25,
FP_MaxRecursionLimitErrorNameEnum = 26,
FP_RecursionStackTraceStrLen = 27,
FP_TouchMetricData = 28,
FP_UndefinedCallErrEnum = 29,
FP_NavigatorPropertiesHash = 30,
FP_CodecPlayabilityBitfield = 31,
```

Most of the values in this part of the fingerprint are pretty basic, and just try to establish basic properties of your browser. The most invasive thing sent within this is your GPU.

Each value is encoded a certain way.
There are a couple of types it can be:
```js
DATATYPE_UNK = 1, // this is an empty value
DATATYPE_UNK2 = 2, // this is an empty value
B2H = 3, // This encodes one byte
SERIALIZED_BYTE_ARRAY = 4, // This encodes a byte array
B2H_WITH_CHECKS = 5, // This encodes 1 or 2 bytes depending on the size of the value
B2H_ROUNDED = 6, // This rounds the value * 10, then encodes to a byte.
JUST_APPEND = 7, // This simply appends a byte array
```

The first byte of the value includes one of the types above, and the index of the fingerprint value type using some bit magic. The rest of the data is reserved for the value.

With this info, and a little bit of size logging, we can now decode the first part of the token.

### Decoded part 1 data from a real token
```python
P1 Info 0 data B2H: 1
P1 Info 1 data B2H: 0
P1 Info 2 data SBA: b'aw'
P1 Info 3 data B2HR: 80
P1 Info 4 data JA: 878004380408
P1 Info 5 data B2H1: 24
P1 Info 6 data B2H1: 24
P1 Info 7 data B2HR: 10
P1 Info 8 data JA: 1000
P1 Info 9 data JA: 027d5fc9a7
P1 Info 10 data JA: 0572930208
P1 Info 11 data JA: 0c007f
P1 Info 12 data: b'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
P1 Info 13 data SBA: b'54b4b5cf'
P1 Info 14 data JA: 0307
P1 Info 17 data B2H: 0
P1 Info 18 data SBA: b'c6749e76'
P1 Info 19 data SBA: b'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002504) Direct3D11 vs_5_0 ps_5_0, D3D11)'
P1 Info 20 data SBA: b'12/31/1969, 7:00:00 PM'
P1 Info 21 data JA: 0800
P1 Info 22 data B2H1: 33
P1 Info 24  data B2H2: 12549
P1 Info 25 data B2H: 0
P1 Info 26 data B2H: 1
P1 Info 27  data B2H2: 4644
P1 Info 28 data JA: 00
P1 Info 29 data B2H: 3
P1 Info 30 data JA: 5dc5abb588
P1 Info 31 data JA: a26a
```

## Decoding the token: Part 2 
The second part of the fingerprint is encoded exactly the same as the first part, but has completely different data.
```js
FP_ConstantOne = 0,
FP2_TimeZone = 1,
FP2_LanguageArray = 2,
FP2_PrivacyBlockerString = 5,
FP2_ExpectedPropertyStringsFoundCount = 6,
FP2_CastleDataBitField = 10,
FP2_BraveDetector2 = 11,
FP2_NegativeErrorLength = 12,
FP2_HtmlFeatureCheck = 13,
FP2_IsPlatformEmpty = 14,
FP2_NotificationPermission = 15,
FP2_JSCheckForWorkerDifferences = 16,
FP2_ChromeFeatureSet = 17,
FP2_DeviceLogicExpected = 18,
FP2_AdBlockerHash = 19,
FP2_ListenerInputBoxTypeBitField = 20,
FP2_ClassPropertiesCount = 21,
FP2_UserLocale2 = 22,
```
This data is a lot more complex in nature than the first part. There are a couple interesting values in here.
### Ad Blocker Hash
This creates a bunch of divs with the names of ads which end up getting blocked by ad blockers. This checks if the divs are present after adding them and creates a hash based on what is there.
![alt text](/images/adblockerddivs.png)


### Privacy Blocker Detection
This checks for privacy blocking browsers or plugins. The following are sent if found: JShelter, NoScript, Puppeteer, PrivacyPossum, PrivacyBadger, DuckDuckGo, Chameleon, CanvasBlocker, Trace, and Brave.
This part seems to be *heavily inspired* by [CreepJS](https://github.com/abrahamjuliot/creepjs/blob/2ca0c340225aa86bf92b7ed6647103f2b7aa6809/src/resistance/index.ts).

### Web Driver Detection
This checks for presence of automation tools such as [Selenium](https://www.selenium.dev/), [Sequentum](https://www.sequentum.com/), [Nightmare](https://github.com/segment-boneyard/nightmare), or [Phantom](https://phantomjs.org/). If these are found, a bitfield with what was found is sent.

#### Selenium
For selenium, they check the following:

```
Selenium_IDE_Recorder
callSelenium
webdriver
_selenium
__webdriver_script_fn
__driver_evaluate
__webdriver_evaluate
__selenium_evaluate
__fxdriver_evaluate
__webdriver_unwrapped
__selenium_unwrapped
__fxdriver_unwrapped
__webdriver_script_fn
__websdriver_script_func
selenium
webdriver
driver
```
#### Nightmare

For Nightmare, they check `__nightmare`.
#### Sequentum
For Sequentum, they check `window.external.toString().contains("Sequentum")`
#### Phantom
For Phantom, they check `callPhantom, _phantom, __phantomas`

### Brave Detection
This value is added if the user is using Brave (by checking if `navigator.brave.isBrave()`), presumably due to its privacy focused additions.

#### Decoded part 2 data from a real token

```python
P2 Info 0 data B2H: 0
P2 Info 1 data SBA: b'America/Aruba'
P2 Info 2 data SBA: b'nl-AW,aw'
P2 Info 6 data B2H1: 0
P2 Info 10 data JA: 040e
P2 Info 12 data B2H1: 80
P2 Info 13 data JA: 090000
P2 Info 17 data JA: 0d0722
P2 Info 18 has no data 1
P2 Info 21 data JA: 00000000
P2 Info 22 data SBA: b'nl-AW'
```


## Decoding the token: Part 3

Part 3 of the fingerprint has a heavy emphasis on input and event values. They monitor the following events: 
1. keyup
2. keydown
3. click
4. mouseup
5. mousedown
6. touchend
7. touchstart
8. touchcancel
9. mousemove
10. touchmove
11. devicemotion
12. wheel

The first value is a bitfield with some general values to check if you are on a touch device or if a certain event has occured:
```js
p1 = [
    0 < DataPoint_Mouse_TimeDiff_KeyDownUp_1000.G.p,
    IsTouchValue(),
    0 < GetEventValue(EVENT_CLICK),
    0 < KeyDownCount.p,
    GetEventValue(EVENT_DEVICEMMOTION) > Ci &&
        (null != (a = divNegativeDivisor(OrientationDataPoint.G))
        ? a
        : ZeroConstant) > Ci,
    0 < BackspaceCount.p,
    0 < NotTouchCount.p,
    !!(a = EventArrLookup(UNK_CONST_0)) &&
        a.C === ZeroConstant &&
        a.k === ZeroConstant,
]
```

The next values are custom floats which fit in one byte.

For values greater than 128: encode float with 4 bytes for exponent, 3 bits for mantissa.

For values less than 128: encode float with 2 bytes for exponent, 4 bits for mantissa.

These actual values range from differences in time between events to differences in angle between events. The reversed values are laid out here:

```js
p2 = [
    divNegativeDivisor(DataPoint_Mouse_AngleVector_500.G),  // index 0
    divNegativeDivisor(DataPoint_Touch_AngleVector.G),  // index 1
    divAndRoundDataPoint(DataPoint_Key_KeysSameTimeDiff_1000.G),  // index 2
    divAndRoundDataPoint(DataPoint_Key_TimeDiff_SpecialKey_Up.G),  // index 3
    divAndRoundDataPoint(DataPoint_Mouse_TimeDiff_MouseDownUp.G),  // index 4
    divNegativeDivisor(data2.G),  // index 5
    GetDataMedianRounded(DataPoint_Mouse_Click_TimeDiff.G),  // index 6
    GetDataAbsoluteDeviation(DataPoint_Mouse_Click_TimeDiff.G),  // index 7
    GetDataMedianRounded(DataPoint_Mouse_TimeDiff_MouseDownUp.G),  // index 8
    GetDataAbsoluteDeviation(DataPoint_Mouse_TimeDiff_MouseDownUp.G),  // index 9
    GetDataMedianRounded(DataPoint_Key_TimmeDiff_ClickDown.G),  // index 10
    GetDataAbsoluteDeviation(DataPoint_Key_TimmeDiff_ClickDown.G),  // index 11
    GetDataMedianRounded(DataPoint_Key_TimeDiff_SpecialKey_Down.G),  // index 12
    GetDataAbsoluteDeviation(DataPoint_Key_TimeDiff_SpecialKey_Down.G),  // index 13
    GetDataMedianRounded(DataPoint_Key_TimeDiff_SpecialKey_Up.G),  // index 14
    GetDataAbsoluteDeviation(DataPoint_Key_TimeDiff_SpecialKey_Up.G),  // index 15
    GetDataMedianRounded(DataPoint_Key_TimeDiff_SpecialKey_DownUp.G),  // index 16
    GetDataAbsoluteDeviation(DataPoint_Key_TimeDiff_SpecialKey_DownUp.G),  // index 17
    GetDataMedianRounded(DataPoint_Key_TimeDiff_SpecialKey_UpDown.G),  // index 18
    GetDataAbsoluteDeviation(DataPoint_Key_TimeDiff_SpecialKey_UpDown.G),  // index 19
    GetDataMedianRounded(DataPoint_Mouse_VectorAngle.G),  // index 20
    GetDataAbsoluteDeviation(DataPoint_Mouse_VectorAngle.G),  // index 21
    GetDataMedianRounded(DataPoint_Mouse_VectorAngle_500.G),  // index 22
    GetDataAbsoluteDeviation(DataPoint_Mouse_VectorAngle_500.G),  // index 23
    GetDataMedianRounded(DataPoint_Mouse_Deviation.G),  // index 24
    GetDataAbsoluteDeviation(DataPoint_Mouse_Deviation.G),  // index 25
    roundToDecimalPlaces(DataPoint_Mouse_Deviation.G.L),  // index 26
    roundToDecimalPlaces(DataPoint_Mouse_Deviation.M),  // index 27
    GetDataMedianRounded(DataPoint_Touch_Sequential_TimeDiff.G),  // index 28
    GetDataAbsoluteDeviation(DataPoint_Touch_Sequential_TimeDiff.G),  // index 29
    GetDataMedianRounded(DataPoint_Touch_TimeDiff_StartEndCancel.G),  // index 30
    GetDataAbsoluteDeviation(DataPoint_Touch_TimeDiff_StartEndCancel.G),  // index 31
    MathAbsDiff(GetDataMedianRounded(DataPoint_KeyTimeDiff_LetterDigit.G), timeDiff_LetterLetter_Meidan),  // index 32
    MathAbsDiff(GetDataAbsoluteDeviation(DataPoint_KeyTimeDiff_LetterDigit.G), data),  // index 33
    MathAbsDiff(GetDataMedianRounded(DataPoint_KeyTimeDiff_DigitInvalid.G), timeDiff_LetterLetter_Meidan),  // index 34
    MathAbsDiff(GetDataAbsoluteDeviation(DataPoint_KeyTimeDiff_DigitInvalid.G), data),  // index 35
    MathAbsDiff(GetDataMedianRounded(DataPoint_KeyTimeDiff_DoubleInvalid.G), timeDiff_LetterLetter_Meidan),  // index 36
    MathAbsDiff(GetDataAbsoluteDeviation(DataPoint_KeyTimeDiff_DoubleInvalid.G), data),  // index 37
    GetDataMedianRounded(DataPointMouseVectorDiffMedian),  // index 38
    GetDataAbsoluteDeviation(DataPointMouseVectorDiffDeviation),  // index 39
    GetDataMedianRounded(DataPoint_mouse_VectorDiff_Median),  // index 40
    GetDataAbsoluteDeviation(DataPoint_mouse_VectorDiff_Deviation),  // index 41
    GetDataMidpointRounded2(DataPoint_Mouse_VectorDiff_Threshold500.G),  // index 42
    GetMedianAbsoluteDeviationCalculator2(DataPoint_Mouse_VectorDiff_Threshold500.G),  // index 43
    GetDataMedianRounded(DataPoint_mouse_TimeDiff_Rounded),  // index 44
    GetDataAbsoluteDeviation(DataPoint_mouse_TimeDiff_Rounded),  // index 45
    GetDataMedianRounded(DataPoint_mouse_VectorDiff_Rounded),  // index 46
    GetDataAbsoluteDeviation(DataPoint_mouse_VectorDiff_Rounded),  // index 47
    GetDataMedianRounded(DataPoint_mouse_ChangeSpeed),  // index 48
    GetDataAbsoluteDeviation(DataPoint_mouse_ChangeSpeed),  // index 49
    GetRoundedDataPointValue(DataPoint_Mouse_VectorDiff_Threshold500.G),  // index 50
    GetDataMedianRounded(DataPoint_Universal.G),  // index 51
    GetDataAbsoluteDeviation(DataPoint_Universal.G)  // index 52
]
```

Finally, they encode the how many times a certain event type has been fired. These are simply appended as hex bytes.
The value is scaled on a range of 0-255.
```js
p3 =  [
    scaleAndCapValue(GetEventCounter(EVENT_MOUSEMOVE)),
    scaleAndCapValue(GetEventCounter(EVENT_KEYUP)),
    scaleAndCapValue(GetEventCounter(EVENT_CLICK)),
    scaleAndCapValue(GetEventCounter(EVENT_TOUCHSTART)),
    scaleAndCapValue(GetEventCounter(EVENT_KEYDOWN)),
    scaleAndCapValue(GetEventCounter(EVENT_TOUCHMOVE)),
    scaleAndCapValue(MathAbsDiff(GetEventCounter(EVENT_MOUSEDOWN),GetEventCounter(EVENT_MOUSEUP))),
    scaleAndCapValue(1 < DataPoint_mouse_VectorDiff_Rounded.p ? DataPoint_mouse_VectorDiff_Rounded.p - 1 : ZeroConstant),
    scaleAndCapValue(WheelDataPointCounter.p)
]
```

### Decoded part 3 of the token

```python
Bitfield: 0b100001001000000
Float 0 40.0
Float 1 0
Float 2 78.0
Float 3 0
Float 4 66.0
Float 5 0
Float 6 0.0
Float 7 0.0
Float 8 74.0
Float 9 6.0
Float 10 36.0
Float 11 2.75
Float 12 0
Float 13 0
Float 14 0
Float 15 0
Float 16 0
Float 17 0
Float 18 0
Float 19 0
Float 20 174.0
Float 21 5.25
Float 22 142.0
Float 23 3.25
Float 24 1.75
Float 25 0.8125
Float 26 0.0
Float 27 0.0
Float 28 0
Float 29 0
Float 30 0
Float 31 0
Float 32 0.0
Float 33 0.0
Float 34 0.0
Float 35 0.0
Float 36 0.0
Float 37 0.0
Float 38 1.0
Float 39 0.0
Float 40 1.0
Float 41 0.0
Float 42 3.75
Float 43 1.0
Float 44 40.0
Float 45 40.0
Float 46 34.0
Float 47 27.0
Float 48 1.5
Float 49 0.0
Float 50 0.75
Float 51 1.0
Float 52 0.0
Int 0 171
Int 1 3
Int 2 1
Int 3 0
Int 4 3
Int 5 0
Int 6 0
Int 7 0
Int 8 0
```

## Encrypting the token
Now that we understand the data going into the fingerprint, how do we encode it?
1. Generate a string based off the current timestamp. 
2. Derive a key from this string, and xor all the fingerprint data with this key.
3. Derive a key from the CUID cookie (a random 16 byte string), and xor the encrypted data + the previous key.
4. A preamble/header is generated. This includes a prefix of "09", the public key for the site, an encoded value representing the fingerprint version, and your CUID cookie.
5. The fingerprint size thus far is appended as one byte (if over 255 long, it will simply mask it to one byte).
6. A random byte is generated, and all the data is xored one more time, and the random byte is appended to the result. 
7. Encode the final data with Base64(URL), and strip any padding.

Using all the data we've gathered, we can generate completely new fingerprints, and decode existing tokens to extract data from by following this method in reverse.

## Conclusion

Castle.io’s ``X-Castle-Request-Token`` is a sophisticated mechanism for gathering and analyzing browser fingerprint data. By decoding its components, we can gain insights into its operations and even replicate its behavior. The code to generate and decode tokens, along with further specifics, is all available on my [repository](https://github.com/yubie-re/castleio-gen).