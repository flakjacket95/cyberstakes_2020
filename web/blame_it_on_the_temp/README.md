# Blame It On The Temp (Web 150)

# Analysis
At first glance, this website provided a means to upload files, which immediately stood out as a piece of the vulnerability. However, as the hints suggest, the website utilizes the templating engine (Jinja2) to render the webpage. This provides us a second piece of this puzzle. With both together, we can upload a new template and then load it (called Server Side Template Injection or SSTI).

The website actually gave us a template change dropdown, which hinted further at the intended solution.

# Approach
To begin, I wanted to upload a fake file to the `app/templates` directory, but, I was noticing an odd filename filtering, every `/` was translated into a `:`. After nearly a day wondering how to take advantage of the upload vulnerability (during which I was too lazy to download BurpSuite) I realized this filtering was actually my operating system, and not the website. I downloaded and setup BurpSuite, and used that from then on.

From there, I decided to attempt uploading templates. I tried to upload a file to change the `Default` template, so I created a basic SSTI test file, like below, and uploaded it as `../../app/templates/Default`.
```python
{{ 7 * '7' }}
```
This gave me a very interesting error message: `CTF Warning: Get your own folder.` After thinking about this for a bit, I decided to try a different file name, same file, but uploading to `../../app/templates/MyTemplate`. This time it uploaded, I then edited the template dropdown to select `MyTemplate` and submitted it, and it reloaded the main page...no dice.

After rethinking a bit, I realized what I had overlooked in the above error message, the word `folder`. I decided to attempt throwing my template in a folder, `../../app/templates/MyTemplate/index.html`. This uploaded, and suddenly the template dropdown changed to include `MyTemplate` as an option. I selected it, and a page loaded with `7777777`, perfect...now to find the flag.

I first decided to attempt reading the config variables, so, I copied the payload off of PayloadsAllTheThings:
```python
{{config.items()}}
```
This worked, but, I saw no flags. So, I presumed maybe it would be in a file instead. I tried the other payloads, none worked, so, I looked for an approach that described how to form an SSTI payload. I did notice, that after using one template folder name, I would have to change it to get the next one to properly work. So, for each test, I incremented a counter in my template name by one.

I first learned about using a string to access a class object, which would be done via `''.__class__.__mro__`. This works because the MRO call will show a list of what objects the string object is derived from, so, in this case, I can see a string it derived from the `object` class. I saw the result from this was as follows:
```
(<class 'str'>, <class 'object'>)
```
So, to  further my exploit, I should add a `[1]` and then I can see a list of subclasses available in the root object (which would be all available), with `__subclasses__()`. This returns the following:
```
[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>,
...
]
```
Looking through that, I noticed that `<class 'subprocess.Popen'>` was loaded, which, I could make use of. I selected the offset for that class, which came out to 287. I then simply called it as a function with the same arguments and processes I normally would in python.

# Solution
Upload the following file to an unused template location, `../../app/templates/MyTemplate22/index.html`
```python
{{ ''.__class__.__mro__[1].__subclasses__()[287]('cat flag',shell=True,stdout=-1).communicate()[0].strip() }}
```
