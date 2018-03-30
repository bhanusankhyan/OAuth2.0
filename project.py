from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
from flask import session as login_session
import string, random
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu"

#Connect to Database and create database session
engine = create_engine('postgresql+psycopg2://bhanu:bhanu@localhost/restaurant')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_uppercase+string.digits) for x in range(32))
    login_session['state']=state
    return render_template('login.html',STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
      # If the tokens don't match return a 401 error
    if request.args.get('state') != login_session['state']:
       response = make_response(json.dumps('Invalid state parameter.'), 401)
       response.headers['Content-Type'] = 'application/json'
       return response
    code = request.data
    try:
       # Upgrade the auth code into a credentials object
       oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
       oauth_flow.redirect_uri = 'postmessage'
       credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
       response = make_response(json.dumps('Failed to upgrade the auth code.'), 401)
       response.headers['Content-Type'] = 'application/json'
       return response
    access_token = credentials.access_token
    # Verify the access token
    url = ('https://www.googleapis.com/oauth2/v2/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    req = h.request(url,'GET')[1]
    req_json = req.decode('utf-8').replace(" ' ",' " ')
    result = json.loads(req_json)
    if result.get('error') is not None:
       response = make_response(json.dumps(result.get('error')), 500)
       response.headers['Content-Type'] = 'application/json'
       return response
    # Verify that the access token is for the correct user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
       response = make_response(json.dumps(result.get('Token users do not match')), 401)
       response.headers['Content-Type'] = 'application/json'
       return response
    # Verify that the access token is for the correct app
    if result['issued_to'] != CLIENT_ID:
       response = make_response(json.dumps(result.get('Token apps do not match')), 401)
       response.headers['Content-Type'] = 'application/json'
       return response
    # Check to see if user already logged-in
    stored_access_token = login_session.get('access_token')
    stored_gplus_id     = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
       response = make_response(json.dumps(result.get('Current user is already logged-in')), 200)
       response.headers['Content-Type'] = 'application/json'
    # Store the user credentials
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id']     = gplus_id
    # Okay, everything checks out now lets get some user details
    userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    # Store the user details in the session
    login_session['username'] = data["name"]
    login_session['picture']  = data["picture"]
    login_session['email']    = data["email"]
    # Create User unless it is already stored; store user_id



    # Now return the user details as HTML
    output = ""
    output += "<h1>Welcome, "
    output += login_session['username']
    output += "!</h1>"
    output += "<img src='"
    output += login_session['picture']
    output += "' style = 'width: 300px; height: 300px; border-radius: 150 px;"
    output += " -webkit-border-radius: 150px; -moz-border-radius: 150px;'>"
    flash("You are now logged in as %s" % login_session['username'])
    return output





def getUserID(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None

def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user

def createUser(login_session):
    newUser = User(name = login_session['username'], email = login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.email


@app.route('/logout')
def logout():

    if 'username' not in login_session:
       return redirect(url_for('showRestaurants'))

    stored_username = login_session.get('username')
    # print "In logout, current user is '%s'" % stored_username
    stored_access_token = login_session.get('access_token')
    # Only all connected users to log out
    if stored_access_token is None:
       print ("In logout, access token for user '%s' is None!" % stored_username)
       response = make_response(json.dumps('Current user not connected.'), 401)
       response.headers['Content-Type'] = 'application/json'
       return response
    # Revoke the access token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % stored_access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    # print 'In logout, revoke result = ', result
    if result['status'] == '200':
       print ("In logout, user '%s' successfully logged out" % stored_username)
       # Reset the user's session
       del login_session['access_token']
       del login_session['gplus_id']
       del login_session['username']
       del login_session['picture']
       del login_session['email']
       #del login_session['user_id']
       response = make_response(json.dumps('Current user logged out.'), 200)
       response.headers['Content-Type'] = 'application/json'
       return response

    else:
       print ("In logout, failed to revoke token for user '%s' response was '%s'" % (stored_username, result['status']))
       # Send a failure message
       response = make_response(json.dumps('Failed to revoke token for current user.'), 400)
       response.headers['Content-Type'] = 'application/json'
       return response

#JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id = menu_id).one()
    return jsonify(Menu_Item = Menu_Item.serialize)

@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants= [r.serialize for r in restaurants])


#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
  restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
  return render_template('restaurants.html', restaurants = restaurants)

#Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def newRestaurant():
  if 'username' not in login_session:
      flash("Please Login first")
      return redirect('/restaurant')
  if request.method == 'POST':
      newRestaurant = Restaurant(name = request.form['name'])
      session.add(newRestaurant)
      flash('New Restaurant %s Successfully Created' % newRestaurant.name)
      session.commit()
      return redirect(url_for('showRestaurants'))
  else:
      return render_template('newRestaurant.html')

#Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
  if 'username' not in login_session:
      flash('PLease login first')
      return redirect('/restaurant')
  editedRestaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if request.method == 'POST':
      if request.form['name']:
        editedRestaurant.name = request.form['name']
        flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
        return redirect(url_for('showRestaurants'))
  else:
    return render_template('editRestaurant.html', restaurant = editedRestaurant)


#Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
def deleteRestaurant(restaurant_id):
    try:

        if 'username' not in loggin_session:
          flash('Please login first')
          return redirect('/restaurant')
        restaurantToDelete = session.query(Restaurant).filter_by(id = restaurant_id).one()
        if request.method == 'POST':
          session.delete(restaurantToDelete)
          flash('%s Successfully Deleted' % restaurantToDelete.name)
          session.commit()
          return redirect(url_for('showRestaurants', restaurant_id = restaurant_id))
        else:
          return render_template('deleteRestaurant.html',restaurant = restaurantToDelete)
    except:
        flash('Please login first')
        return redirect('/restaurant')

#Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return render_template('menu.html', items = items, restaurant = restaurant)



#Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
    try:

        if 'username' not in loggin_session:
          flash('Please Login first')
          return redirect('/restaurant')
        restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
        if request.method == 'POST':
          newItem = MenuItem(name = request.form['name'], description = request.form['description'], price = request.form['price'], course = request.form['course'], restaurant_id = restaurant_id)
          session.add(newItem)
          session.commit()
          flash('New Menu %s Item Successfully Created' % (newItem.name))
          return redirect(url_for('showMenu', restaurant_id = restaurant_id))
        else:
          return render_template('newmenuitem.html', restaurant_id = restaurant_id)
    except:
        flash("Please Login first")
        return redirect('/restaurant')


#Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):
    try:

        if 'username' not in loggin_session:
          flash('Please Login first')
          return redirect('/restaurant')

        editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
        restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
        if request.method == 'POST':
             if request.form['name']:
                editedItem.name = request.form['name']
             if request.form['description']:
                editedItem.description = request.form['description']
             if request.form['price']:
                editedItem.price = request.form['price']
             if request.form['course']:
                editedItem.course = request.form['course']
             session.add(editedItem)
             session.commit()
             flash('Menu Item Successfully Edited')
             return redirect(url_for('showMenu', restaurant_id = restaurant_id))
        else:
            return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)
    except:
        flash('Please Login First')
        return redirect('/restaurant')

#Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id,menu_id):
    try:

        if 'username' not in loggin_session:
           flash('Please Login first')
           return redirect('/restaurant')
        restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
        itemToDelete = session.query(MenuItem).filter_by(id = menu_id).one()
        if request.method == 'POST':
           session.delete(itemToDelete)
           session.commit()
           flash('Menu Item Successfully Deleted')
           return redirect(url_for('showMenu', restaurant_id = restaurant_id))
        else:
           return render_template('deleteMenuItem.html', item = itemToDelete)
    except:
        flash('Please login first')
        return redirect('/restaurant')





if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
