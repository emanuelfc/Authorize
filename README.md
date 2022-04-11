# Authorize

Authorize is a Burp Extension, built in Java, aimed at helping identifying Authorization and Access Control flaws, and any other where it may apply.

It intercepts Burp requests, and performs an authenticated request - for each specified User (User) - and analyzes the server's response, identifying the Enforcement Status of the User's request (basically, if the response contains unauthorized information or an unauthorized action was successfully performed)

(Inspired by Autorize and AuthMatrix)

## Features

**Persistent Proxy History and Settings**

Authorize is able to save all of its proxy history messages and settings within the current Burp project saved on disk. You don't have to worry about losing this data and having to later re-configure the settings.

**Import and Export Settings**

Settings can be exported in JSON format, and later imported. This allows a user to safely share its own settings to other team members when performing penetration tests, backup the settings, or create a template to be imported for each project - its up to the user.

**Customizable per-User (User) Rules**

Each User contains a set of individual rules that are only applied to it when performing and operation on the User - such as sending a request as that User. This grants fine-grained control over User actions, allowing to control User behaviour on a per-user basis, without affecting the behaviour of other users.

**Customizable Global Rules**

In addition to per-user settings, you are also able to set global rules - rules which are applied to all requests intercept or created by Authorized, allowing for more coarse-grained control.

**Tests**

You can save proxy messages as tests, for easier retesting - allowing you not only to identify but also modify them freely.

## Disclaimer

The application is in development but ready for use. If you encounter any issues, such as crashes, please report it!
