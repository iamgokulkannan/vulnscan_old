password = '@Vi3iq4y8'
email = 'bugtesting@gmail.com'
strings = ['red', 'bob', 'admin', 'alex', 'testing',
           'test', 'lol', 'yes', 'dragon', 'bad']  # list of generic, often-used words that may appear in usernames or weak passwords
# list of common variable or parameter names often found in web applications
commonNames = ['csrf', 'auth', 'token', 'verify', 'hash']
tokenPattern = r'^[\w\-_+=/]{14,256}$'  # regex token pattern

headers = {  # Custom Header
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip,deflate,br',  # 'br' is for Brotli compression
    'Connection': 'close',
    'DNT': '1',  # Do Not Track
    'Upgrade-Insecure-Requests': '1',
    # Custom User-Agent string
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0',
    'Referer': 'https://www.example.com/',  # Referrer URL for context
    'Cache-Control': 'no-cache',  # Disable caching
    'Pragma': 'no-cache',  # Legacy header for cache control
    # MIME type for form submissions
    'Content-Type': 'application/x-www-form-urlencoded',
    # Used for API requests with token-based authentication
    'Authorization': 'Bearer <token>',
    'X-Requested-With': 'XMLHttpRequest',  # Indicates AJAX request
    'Origin': 'https://www.example.com',  # Originating site for CORS
    'Host': 'www.example.com',  # Host header to specify the domain being requested
    # Used for conditional GET requests
    'If-Modified-Since': 'Sat, 29 Oct 1994 19:43:31 GMT',
}
