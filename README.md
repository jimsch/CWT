# CWT - a CBOR Web Token implementation in C#

[![NuGet Status](https://img.shields.io/nuget/v/Com.AugustCellars.CWT.png)](https://www.nuget.org/packages/Com.AugustCellars.CWT)
[![Build Status](https://api.travis-ci.org/jimsch/CWT.png)](https://travis-ci.org/jimsch/CWT)

The CBOR Web Token (https://datatracker.ietf.org/doc/draft-ietf-ace-cbor-web-token/) is a compact means to representing claims being transfered between two parites.
A claim is a piece of information, such as a key or an identity, that is being asserted about a subject.
CWT is an implementation in C# of these tokens which are being used to provide authentication and authorization information for the CoAP world.

Reviews and suggestions are appreciated.  The current API should not be considered to be stabled and may changed at any time.

Any body who has suggestions or problems, please file either an issue or a pull request to this project.

## Copyright

Copyright (c) 2017, Jim Schaad <ietf@augustcellars.com>

## Content

- [Quick Start](#quick-start)
- [License](#license)
- [Acknowledgments](#Acknowledgments)

## How to install

The C# implementation is available in the NuGet Package Gallery under the name [Com.AugustCellars.CWT](https://www.nuget.org/packages/Com.AugustCellars.CWT).
To install this library as a NuGet package, enter 'Install-Package Com.AugustCellars.CWT' in the NuGet Package Manager Console.

## Documentation

To be done

## Quick Start

### Creation

### Verification and Use

## License

See [LICENSE](LICENSE) for more info.

## Acknowledgments

This work is based on the CWT specification and uses COSE and CBOR libraries which have been made freely available.
