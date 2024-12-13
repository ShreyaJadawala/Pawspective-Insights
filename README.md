# Pawspective-Insights

steps to test the code on docker:

1. docker build -t paw-webapi:10.0 .
2. docker run -d -p 8000:8000 --name paw-webapi paw-webapi:10.0
( IF THIS WORKS)

PUSHING THE CODE TO AZURE
3. docker login demosj1607.azurecr.io (LOGIN TO REGISTERY ON AZURE)
4. docker tag paw-webapi:10.0 demosj1607.azurecr.io/paw-webapi:10.0 (MAKING THE COPY FOR PUSHING CODE TO REGISTERY)
5. docker push demosj1607.azurecr.io/paw-webapi:10.0 (PUSHING THE CODE TO AZURE)

