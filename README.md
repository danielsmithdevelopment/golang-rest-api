# golang-rest-api
Using Golang to write a RESTful server/api. Connects to a local database and provides Create, Read, Update, Delete functionality. Templated with go templates to render front end.

To start server, start local mysql instance and then run:

```
git clone git@github.com:danielsmithdevelopment/golang-rest-api.git
cd golang-rest-api
go get -d ./...
go build -o main
./main
```