from flask import Flask, request, jsonify
from pymongo import MongoClient
import re

app = Flask(__name__)
client = MongoClient()  # defaults to localhost:27017
db = client.data

@app.route('/ssl')
def search_ssl():
    search_string = request.args.get('search_string')
    if not search_string or len(search_string) < 3:
        return 'Search string must be at least 3 characters long', 400

    query = {"$or": [{"subjectAltName": {"$regex": f"{re.escape(search_string)}"}},
                     {"subjectCN": {"$regex": f"{re.escape(search_string)}"}},
                     {"issuer": {"$regex": f"{re.escape(search_string)}"}}]}
    projection = {"_id": 0}

    result = db.ssl.find(query, projection).limit(2000)
    docs = []
    for doc in result:
        docs.append(doc)

    return jsonify(docs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
