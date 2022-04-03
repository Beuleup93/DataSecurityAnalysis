library(tidyverse)
library(dplyr)
library(tidyr)
library(lubridate) 
library(scales) 
library(cluster)
library(readr)
library(RMySQL)
library(lubridate)
library(rpart)
library(rpart.plot)
library(FactoMineR)


# PARAMETRE DE CONNEXION BASE DE DONNEE MYSQL, A ADAPTER SELON LES INFORMATIONS DE CONNEXIONS
options(mysql = list(
  "host" = "127.0.0.1",
  "port" = 8889,
  "user" = "root",
  "password" = "root",
  "databaseName" = "bd_securite"
))


getSingleConnexion <- function(){
  db <- dbConnect(MySQL(),
                  dbname = options()$mysql$databaseName,
                  host = options()$mysql$host,
                  port = options()$mysql$port,
                  user = options()$mysql$user,
                  password = options()$mysql$password)
  return(db)
}

# Test connection
#summary(getSingleConnexion())

# Insertion des données dns la base de données 
loadDataFromFile <- function(){
  #df <- read_delim("~/Documents/challenge-2021/données/logs_fw-4.csv",delim = ";", escape_double = FALSE, trim_ws = TRUE)
  df = read_delim("~/Downloads/Simulation_data.csv", delim = ";", escape_double = FALSE, trim_ws = TRUE)
  #df$datetimestamp = NULL
  #df$countryipsrc = NULL
  #df$tdst = NULL
  db <- getSingleConnexion()
  apply(df, 1, function(row){
    # Build Query
    query <-sprintf(
      "INSERT INTO %s (%s,%s, %s,%s,%s,%s,%s,%s,%s,%s) VALUES (%s,%s,'%s','%s','%s','%s','%s','%s','%s','%s')",
      "log_file",
      paste("id", collapse = ", "),
      paste("fwid", collapse = ", "),
      paste("datetime", collapse = ", "),
      paste("ipsrc", collapse = ", "),
      paste("ipdst", collapse = ", "),
      paste("dstport", collapse = ", "),
      paste("proto", collapse = ", "),
      paste("action", collapse = ", "),
      paste("policyid", collapse = ", "),
      paste("tsrc", collapse = ", "),
      
      paste(as.numeric(gtNumberOfRows()[,1]+2), collapse = ", "),
      paste(0, collapse = ", "),
      paste(row[1], collapse = ", "),
      paste(row[2], collapse = ", "),
      paste(row[3], collapse = ", "),
      paste(row[5], collapse = ", "),
      paste(row[4], collapse = ", "),
      paste(row[7], collapse = ", "),
      paste(row[6], collapse = ", "),
      paste(row[8], collapse = ", "))
    # Insert Row In DB
    res = dbGetQuery(db, query)
  })
  dbDisconnect(db)
}
#loadDataFromFile()

# CHARGEMENT DES LOG DEPUIS LA BASE DE DONNÉES
getLogFromBD<- function(table, limite=NA){
  db <- getSingleConnexion()
  if(is.na(limite)){
    query <- sprintf("SELECT * FROM %s ",table)
  }else{
    query <- sprintf("SELECT * FROM %s LIMIT %s",table,limite)
  }
  res = dbGetQuery(db, query)
  dbDisconnect(db)
  res$dstport = as.integer(res$dstport)
  return(res)
}


# APPRENTISSAGE SUPPERVISE
supervised_learning <- function(df, positive_mod='DENY', taille=1000){
  df$id =NULL
  df$fwid =NULL
  df = head(df, n=taille)
  #construire un arbre de décision
  arbre <- rpart(action ~ ., data = df)
  return(arbre)
}


acm <- function(df, taille=100){
  df = head(df, n=taille)
  rownames(df) <- df$id
  df$datetime = as.factor(df$datetime)
  df$dstport = as.factor(df$dstport)
  df$ipsrc = as.factor(df$ipsrc)
  df$ipdst = as.factor(df$ipdst)
  df$tsrc = as.factor(df$tsrc)
  df$proto = as.factor(df$proto)
  df$policyid = as.factor(df$policyid)
  df$action = as.factor(df$action)
  df$id = NULL
  df$fwid = NULL
  df = df %>% select(c("datetime","dstport","ipsrc","ipdst","policyid","proto","action"))
  res.acm <- MCA(df, quali.sup = 7, level.ventil = 0)
  return(res.acm)
}

gtNumberOfRows<- function(){
  db <- getSingleConnexion()
  query <- sprintf("SELECT count(*) FROM log_file")
  res = dbGetQuery(db, query)
  dbDisconnect(db)
  return(res)
}

getTypeData <- function(type = 'Données simulées', limit=100){
  db <- getSingleConnexion()
  if(type == 'Données simulées'){
    query <- sprintf("SELECT * FROM log_file where fwid=0 LIMIT  %s",limit)
  }else{
    query <- sprintf("SELECT * FROM log_file where fwid=1 limit %s",limit)
  }
  res = dbGetQuery(db, query)
  dbDisconnect(db)
  res$dstport = as.integer(res$dstport)
  return(res)
}


