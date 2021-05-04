from flask import render_template

from tracker import tracker


@tracker.route('/', methods=['GET'])
def home():
    return render_template('home.html')
