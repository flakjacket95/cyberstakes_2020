# Extremely Malicious Language (Web 300)

# Analysis
Based on the name, this challenge seemed to have to do with XML. The three stages of hints made it seem like we were looking for a chain of vulnerabilities. What confused me here was that this chain didn't necessarily mean that each had to be used to reach the next.

The final hint led us to the source code zip, which was very useful, but, missing a file `make.php`. This happened to be the file that actually did the rendering of the map, so, it might have something useful in it -- seeing it's source would be useful.

# Approach
So, first of all, the main piece of the site was hidden behind a login. The hint mentioned something about Xpath, which, as it turns out would act just like an SQL injection.
```
or 1=1
```
Providing the above as a username would result in being logged into the site.

At this stage, we see that there is a textfield with some XML that we can change around and submit, which, then results in a map displayed to us with countries highlighted. The second hint leads us to believe the issue here is called XXE, or XML external entity injection. Let's see if we can make use of an entity to load the source code to that `make.php` file.

After trying a few options on PayloadsAllTheThings, I found that the PHP one worked for me.
```xml
[<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=make.php"> ]
```

Now with the source code, I could look closer at it and see how they were handling their input. First, they did an odd IP address check (which I just assumed worked, when it didn't). The they just called a shell command with the input, so, perfect, I just need to craft an input that will result in a command injection.

This is where I messed up for a while, not realizing I could load the page directly, I tried to use the XXE for an SSRF as well. Turns out simply going to the URL would work, since the docker container would be translating the web requests. I can run the flag binary by injection `'; ./flag #`

```
http://challenge.acictf.com:43323/make.php?country[]=%27%3B%20.%2Fflag%20%23
```

# Solution
Make the following request to get the flag instead of a map.
```
http://challenge.acictf.com:43323/make.php?country[]=%27%3B%20.%2Fflag%20%23
```
