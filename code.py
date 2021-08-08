# To install modules :
# pip install requests-html
# pip install pyfiglet

from requests_html import HTML, HTMLSession
import json
import pyfiglet
from pprint import pprint
session = HTMLSession()

#-----------------------------------------------------------
#code for web scraping
data = {}
print()
print()
print()
print('Scraping data from http://testphp.vulnweb.com/')
r=session.get('http://testphp.vulnweb.com/')
data['links']=[]
for link in r.html.absolute_links:
    data['links'].append(link)



r1 = session.get('http://testphp.vulnweb.com/artists.php')
artists = r1.html.find("#content")[0].find('div.story')
data['artists']=[]
for artist in artists:
    artistName = artist.find("h3",first=True).text
    artistLink = 'http://testphp.vulnweb.com/' + artist.find('a', first=True).attrs['href']
    commentLink = artist.find("p a",first=True).attrs['onclick'].split("'")[1]
    commentLink = 'http://testphp.vulnweb.com/' + commentLink[2:]
    data['artists'].append({
        'artist-name': artistName,
        'artist-link' : artistLink,
        'comment-link' : commentLink
    })


r2= session.get('http://testphp.vulnweb.com/categories.php')

categories= r2.html.find("#content")[0].find('div.story')
data['categories']=[]
for category in categories:
    categoryLink = 'http://testphp.vulnweb.com/' + category.find("a",first=True).attrs['href']
    categoryName = category.find("a h3",first=True).text
    contents=[]
    categoryContents = session.get(categoryLink).html.find("#content div.story")
    for categoryContent in categoryContents:
        productName = categoryContent.find("a h3",first=True).text
        productLink = 'http://testphp.vulnweb.com/' + categoryContent.find('a',first=True).attrs['href']
        imageLink = 'http://testphp.vulnweb.com/' + categoryContent.find('p a',first=True).attrs['href']
        artistName = categoryContent.find("p a")[1].text
        contents.append({
            "product-name":productName,
            "product-link":productLink,
            "product-image":imageLink,
            "artist-name":artistName
        })
    data['categories'].append({
        'category-name':categoryName,
        'category-link':categoryLink,
        'category-contents': contents
    })


with open('data.txt','w') as outfile:
    json.dump(data,outfile,indent =4)
outfile.close()
print()
print('Scraped Data Successfully\n\nSaved to data.txt!')
#-----------------------------------------------------------
#code for sqli
print()
print()
print()
print("---------Checking for SQLi Vulnerability---------")
url= 'http://testphp.vulnweb.com/artists.php?artist=1'
req = session.get(url)

def vulnerable(response):
    errors=["you have an error in your sql syntax;","warning: mysql","unclosed quotation mark after the character string","quoted string not properly terminated"]
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

for v in "\"'":
    url = url + v
    response = session.get(url)
    if vulnerable(response):
        print(pyfiglet.figlet_format('Sqli vulnerability detected!'))
        print('link: ',url)
        break;
#-----------------------------------------------------------
#code for xss
print()
print()
print()
print("---------Checking for XSS Vulnerability---------")

forms = req.html.find('form')
def submitForm(formdetails,value):
    inputs = formdetails['input']
    data={}
    url = formdetails['action']
    for input in inputs:
        if input['type']=='text' or input['type']=='search':
            input['value']=value
        input_name = input.get('name')
        input_value = input.get('value')
        if input_name and input_value:
            data[input_name]=input_value 
    if formdetails['method']=='post':
        return session.post(url,data=data)
    else:
        return session.get(url,params=data)
details=[]
jscode = "<script>alert(1)</script>"
index = 0;
for form in forms:
    action = 'http://testphp.vulnweb.com/'+form.attrs['action']
    method = form.attrs['method']
    input = []
    for intag in form.find('input'):
        inputType = intag.attrs['type']
        inputName = intag.attrs['name']

        input.append({
            "type":inputType,
            "name":inputName,

        })
    details.append({
        'action':action,
        'method':method,
        'input':input
    })
    submission = submitForm(details[index],jscode).content.decode()
    if jscode in submission:
        print(pyfiglet.figlet_format('XSS vulnerability detected!'))
        print('Form Details: ')
        pprint(details[index])
    index+=1

print('\n\n\n')