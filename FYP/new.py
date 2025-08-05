import requests
with requests.Session() as c:
    url = "https://www.google.com"
    foo = 1
    bar = "hello"

    c.get(url)

    csrftoken = c.cookies['XSRF-TOKEN']

    main_data = dict(_token=csrftoken, foo_id=foo, bar_message=bar)
    c.post(url, data=main_data, headers={"Referer": "https://www.google.com"})
