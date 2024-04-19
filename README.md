# Forum

## Objectives

- Create a web forum on a theme
- Create some categories, posts and comments
- Like and dislike posts
- Filtering posts
- Use Sqlite for the Database
- User Authentification
- Moderation

## Sqlite

In order to store the data in your forum (like users, posts, comments, etc.) you will use the database library SQLite. 

SQLite is a popular choice as an embedded database software for local/client storage in application software such as web browsers. It enables you to create a database as well as controlling it by using queries. 

To structure your database and to achieve better performance we highly advise you to take a look at the [entity relationship diagram](https://www.smartdraw.com/entity-relationship-diagram/) and build one based on your own database. - You must use at least one SELECT, one CREATE and one INSERT queries. 

To know more about SQLite you can check the [SQLite page](https://www.sqlite.org/index.html).

## Pages

Your forum should contain at least :

- Main pages :
  - A landing page
  - A login and register page
  - A page to view all categories
  - A page to view all posts inside a category
  - A page to view a post and the comments associated with it

- Creation pages :
  - A page to create a category
  - A page to create a post

- User pages :
  - A page to view your user profile and modify your information
  - A page to view your account activity (posts, comments, likes and dislikes)
  - A page to view other users profile

> [!WARNING] 
> the data display on the pages must be from the database and not hardcodded  

## Authentication

The user must be able to `register` on the forum, by inputting their credentials. You also have to create a `login session` to allow the user access the forum and be able to add posts and comments. 
You should use cookies to allow each user to have only one opened session. Each of this sessions must contain an expiration date. 
It is up to you to decide how long the cookie stays "alive". 

For the user registration you must :

- Ask for a valid email.
    - When the email is already taken return an error message or modal.
- Ask for a username
- Ask for a password
    - The password must be encrypted when stored inside the database.

For the user login you must : 
- Ask for an email or username 
 - Ask for a password 

 The forum must be able to check if the email provided is present in the database and if all credentials are correct. It will check if the password is the same with the one provided and, if the password is not the same, it will return an error response.


## Categories, Posts and Comments

Your Forum will need to be based around a theme, like : video-games, hiking, food, ect...

> [!WARNING] 
> the theme needs to be something legal and not will not be accepted any NSFW, gore or anything related to it

In order to let users communicates around your theme, they will have to be able to create categories, posts and comments.

- Only the connected users can create categories, posts and comments.
- The posts and comments need to be visible publicly, even if the users does not have an account
- Only registers users can like or dislike posts and comments, and they are visible by everyone
- Users can include images inside their posts
    - There are several extensions for images like: JPEG, SVG, PNG, GIF, etc. In this project you have to handle at least JPEG, PNG and GIF types.
    - The max size of the images to load should be 20 mb. If there is an attempt to load an image greater than 20mb, an error message should inform the user that the image is too big.

## Filter

You need to implement a filter mechanism, that will allow users to filter the displayed posts by :

- categories
- created posts
- liked posts

Note that the last two filters are only available for registered users and must refer to the logged in user.

## Moderation
The `forum moderation` will be based on a moderation system. Depending on the access level of a user or the forum set-up, the moderator can approves posted messages before they become publicly visible.

- The filtering can be done depending on the categories of the post being sorted by irrelevant, illegal or insulting.

You should take into account all types of users that can exist in a forum and their levels.

You should implement at least 4 types of users :

### Guests

- These are unregistered-users that can neither post, comment, like or dislike a post. They only have the permission to **see** those posts, comments, likes or dislikes.

### Users

- These are the users that will be able to create, comment, like or dislike posts.

### Moderators

- Moderators, as explained above, are users that have a granted access to special functions :
  - They should be able to monitor the content in the forum by deleting or reporting post to the admin
- To create a moderator the user should request an admin for that role

### Administrators

- Users that manage the technical details required for running the forum. This user must be able to :
  - Promote or demote a normal user to, or from a moderator user.
  - Receive reports from moderators. If the admin receives a report from a moderator, he can respond to that report
  - Delete posts, comments and categories
  
## Security 

For this project you must take into account the security of your forum.

- You should encrypt at least the clients passwords. You can also encrypt the database, for this you will have to create a password for your database.

- Implement secure sessions and cookies 
 - Clients session cookies should be unique. For instance, the session state is stored on the server and the session should present an unique identifier. This way the client has no direct access to it. Therefore, there is no way for attackers to read or tamper with session state.
 

## Instructions

- The application must be written in Go.
- You must handle website errors, HTTPS status.
- You must handle all sort of technical errors.

## Allowed packages

- All [standard Go](https://golang.org/pkg/) packages are allowed.
- [sqlite3](https://github.com/mattn/go-sqlite3)
- [bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt)
- [UUID](https://github.com/gofrs/uuid)

## Bonus

- You will have to create a way to notify users when their posts are :
  - liked/disliked
  - commented

- The implementation of OAUTH2 to be able to create an account and login via Google or Github

## Notation scale

### Functionalities (10)

- Pages, style and respect of your theme (3)
- Authentication (1.5)
- Categories, post and comments (2)
- Filters (1)
- Moderation (2)
- security of your website (0.5)

### Quality of the code (3)

- Versioning (1) 
> tip: make commits with a clear message and commit regularly
- Code quality (respect of the good practices, comments, etc.) (2)

### SoftSkills (2)

- make and respect the todo list (1)
- adopt a professional behavior (1)

### Oral presentation (5)

- Make a clear support , synthetic and understandable by everyone , beautiful and good orthography (2)
- Answer the questions (1)
- Express yourself easily orally (1 and individual)
- Express majors functionalities (1)

### Malus

- Respect time limit of presentation (-0,5 per 2 minutes)
  
