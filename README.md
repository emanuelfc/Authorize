# Authorize

Authorize is a Burp Extension, built in Java, aimed at helping identifying Authorization and Access Control flaws, and any other where it may apply.

It intercepts Burp requests, and performs an authenticated request - for each specified Principal (User) - and analyzes the server's response, identifying the Enforcement Status of the Principal's request (basically, if the response contains unauthorized information or an unauthorized action was successfully performed)

(Inspired by Autorize and AuthMatrix)

## Features

**Persistent Proxy History and Settings**

Authorize is able to save all of its proxy history messages and settings within the current Burp project saved on disk. You don't have to worry about losing this data and having to later re-configure the settings.

**Import and Export Settings**

Settings can be exported in JSON format, and later imported. This allows a user to safely share its own settings to other team members when performing penetration tests, backup the settings, or create a template to be imported for each project - its up to the user.

**Customizable per-Principal (User) Rules**

Each Principal contains a set of individual rules that are only applied to it when performing and operation on the Principal - such as sending a request as that Principal. This grants fine-grained control over Principal actions, allowing to control Principal behaviour on a per-principal basis, without affecting the behaviour of other users.

**Customizable Global Rules**

In addition to per-principal settings, you are also able to set global rules - rules which are applied to all requests intercept or created by Authorized, allowing for more coarse-grained control.

**Tests**

You can save proxy messages as tests, for easier retesting - allowing you not only to identify but also modify them freely.

## Disclaimer

The application is in development but ready for use. If you encounter any issues, such as crashes, please report it!
