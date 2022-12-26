import multiprocessing as mp
import requests
import json
import time
import datetime
import csv

# Get the current date
today = datetime.date.today()

# Get the date two days ago by subtracting a timedelta from the current date
two_days_ago = today - datetime.timedelta(days=2)

# Format the date as a string in the desired format
date_string = two_days_ago.strftime('%Y-%m-%d')


#------------------ actual code---------------------------------

#input variables for the class
token1 = 'AAAAAAAAAAAAAAAAAAAAAI1thwEAAAAA3cC%2FgCKQBLMT5JeNC9O8U4l%2B44E%3DX983si5PM7EEQrPAhox55t3aDmI7t7AH337roJzOaMIUU9sCNN'
token2='AAAAAAAAAAAAAAAAAAAAAFOSkgEAAAAAuWgPALsN1RBd%2BTH89wA8bRpRm4c%3Dk3BycFNCxSoBxRxp1nk0YTCl73IWsZEL1mM78TeXK7yS8UVDf3'
token3='AAAAAAAAAAAAAAAAAAAAAJSSkgEAAAAAslQRvg5pQT5i4g6n8pJ6pmvv8mg%3DYXnwlyyvM6BMNfJUqH2jxsK2JIcHJMnG0AIVFigIm8Lfs3BsyQ'
token4='AAAAAAAAAAAAAAAAAAAAAMKSkgEAAAAAYt9v8XhDEZ2a9i9LUPR6bljlQ9g%3DODwTwgpoLVHv4pRRTvszw1XXB4RrocjjmD89PdQBJ8VlCxUsii'

tweet_fields= "created_at,public_metrics,author_id"
#queryies
start_time = f'{date_string}T12:00:01.000Z'
print('starting vuln ranker')
#open the CSV file
queryList=[]
CVE_dictionary={}

#---------------------- Open the CSV file
with open('CVEVulnTracker.csv', 'r+') as file:
    # Create a CSV reader object
    reader = csv.reader(file)

    # Iterate over the rows in the file
    for cve in reader:
        #print(cve[0])
        #get CVE
        queryList.append(cve[0])
        CVE_dictionary.update({cve[0]:cve})

#print(queryList)

#print(queryList)

#queryList = ['CVE-2022-42821','CVE-2022-37958','CVE-2022-41082','CVE-2022-41080','CVE-2022-41040','CVE-2021-28655','CVE-2021-33621','CVE-2022-42475','CVE-2022-42710','CVE-2022-46689']

queryList1 =queryList[:2]
#print(queryList1)
queryList2=queryList[2:5]
#print(queryList2)
queryList3=queryList[5:8]
#print(queryList3)
queryList4=queryList[8:]
#print(queryList4)

final_CVE={}


def getfollower(ID,token):
    header = {'Authorization': f"Bearer {token}"}
    params = {'user.fields': 'public_metrics', }
    print('*****************************Getting User followers*****************************')
    result = requests.get(f'https://api.twitter.com/2/users/{ID}', params=params, headers=header)
    # print(result.json())
    followers = result.json()['data']['public_metrics']['followers_count']
    print(f'Author ID:{ID} has {followers} Followers')
    return followers


class TwitterClient:
    def __init__(self,token):
        self.token = token

    def search_function(self,queries,tweet_fields,start_time):
        self.queries = queries
        self.tweet_fields=tweet_fields
        headers = {"Authorization": "Bearer {}".format(self.token)}
        for query in queries:
            url = "https://api.twitter.com/2/tweets/search/recent"
            parameters = {
                'query': query,
                'tweet.fields': tweet_fields,
                'start_time': start_time,
                'max_results':'80',
            }
            response = requests.get(url,params=parameters,headers=headers)
            #print(response.json())


            data=response.json()['data']
            # time it took for the response to get the tweets
            timing = response.elapsed.total_seconds()
            #print(timing, 'seconds')
            print(f'Getting Twitter data from {query}')

            Total_tweets= len(data)
            Total_retweet=[]
            Likes = []
            following=[]
            for i in range(len(data)):
                Total_retweet.append(data[i]['public_metrics']['retweet_count'])
                Likes.append(data[i]['public_metrics']['like_count'])
                following.append(data[i]['author_id'])
            #print(Likes)
            #print(followers)
            #print(Total_retweet)

            #algroithm variables
            retweet_Index = int(sum(Total_retweet))/Total_tweets
            #print(retweet_Index)
            followers=[]
            for i in following:
                followers.append(getfollower(i,self.token))
                #time.sleep(10)


            #follower average
            average_followers =int(sum(followers))/Total_tweets
            #print(average_followers)
            Average_likes=[Likes[i]/average_followers for i in range(len(Likes))]
            Average_likes_index=sum(Average_likes)
            P_formula= (Average_likes_index/Total_tweets) + ((average_followers*Total_tweets)/Total_tweets) + retweet_Index + Total_tweets
            print(P_formula/timing, 'score rated')
            final_p=P_formula/timing
            final_CVE.update({query:final_p})



#initialize the class
searchBot1 = TwitterClient(token1)
searchBot2= TwitterClient(token2)
searchBot3= TwitterClient(token3)
searchBot4=TwitterClient(token4)
#activate query
try:
    searchBot1.search_function(queryList1,tweet_fields,start_time)
except:
    print('Censored/No Results')
try:
    searchBot2.search_function(queryList2,tweet_fields,start_time)
except:
    print('Censored/No Results')
try:
    searchBot3.search_function(queryList3,tweet_fields,start_time)
except:
    print('Censored/No Results')
try:
    searchBot4.search_function(queryList4,tweet_fields,start_time)
except:
    print('Censored/No Results')
sorted_cve = sorted(final_CVE.items(), key=lambda x:x[1], reverse=True)
file.close()

newfile = open("CVEVulnTracker.csv","w", newline="")
writer = csv.writer(newfile)

#put in csv again but ordered
for i in sorted_cve:
    link_data = []
    if i[0] in CVE_dictionary:
        #print(CVE_dictionary[i[0]])
        link_data.append((CVE_dictionary[i[0]]))

    writer.writerows(link_data)

    print(link_data)

newfile.close()
