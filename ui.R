library(shiny)
library(shinydashboard)
library(shinyBS)
library(leaflet)
library(shinyjs)
library(shinyWidgets)
library(plotly)
library(ggplot2)

# vidage de la memoire
rm(list=ls())

# Fonction de verification pour installation des packages
packages = c("shinydashboard", "shinycssloaders", "shiny", "shinyWidgets", "DT", 
             "rAmCharts", "dplyr", "highcharter", "lubridate")

#Check des packages
package.check <- lapply(
  packages,
  FUN = function(x) {
    if (!require(x, character.only = TRUE)) {
      install.packages(x, dependencies = TRUE)
      library(x, character.only = TRUE)
    }
  }
)

header <- dashboardHeader(title = "Data Security",
                          dropdownMenuOutput("notifications"))

sidebar <- dashboardSidebar(
  
  sidebarMenu(
    menuItem("Tableau de bord", tabName = "dashboard",icon = icon("dashboard")),
    
    menuItem("Données", icon = icon("th"), tabName = "donnee"),
    
    menuItem("Analyse descriptive", icon = icon("file-code-o"),
             menuSubItem("Analyse descriptive", tabName = "analysedesc"),
             menuSubItem("Flux protocole", tabName = "action"),
             menuSubItem("Classement adresse et ports", tabName = "analyse"),
             menuSubItem("Protocol UDP & TCP", tabName = "udptcp"),
             menuSubItem("Analyse temporelle", tabName="analysetemporelle"),
             menuItem("Heure d'attaque", tabName = "heure", icon = icon("tree")),
             menuSubItem("Non IP Université", tabName="universite"),
             menuSubItem("Visualisation interactive", tabName="interactive")),
    
    menuItem("ACm", icon = icon("users"), tabName = "acm"),
    
    menuItem("Apprentissage supervisé", icon = icon("users"), tabName = "apprentissage"),
    
    radioButtons("dtype", "Type de données",choices = c("Données simulées","fichier de données")),
    
    numericInput(inputId = "limit",label = "LIMIT DATA",value = 100, min = 1, max = 2951175, step=1)
  )
)

body <- dashboardBody(
  
  tabItems(
    tabItem(tabName = "dashboard",
            fluidRow(
              infoBoxOutput(width = 4, "Item1"),
              infoBoxOutput(width = 4, "Item2"),
              infoBoxOutput(width = 4, "Item3")
            ),
            fluidRow(
              column(6, h3("Actions réalisées par le firewall", align="center"), amChartsOutput(outputId = "statdesc1")),
              column(6, h3("Top 10 des ports inférieurs à 1024 avec un accès autorisé", align="center"), amChartsOutput(outputId = "statdesc3")),
              column(6, h3("Rapprochements entre les règles et les ports de destination", align = "center"), highchartOutput("wheel")),
              column(6, h3("Rapprochements entre les règles et les actions (PERMIT/DENY)", align = "center"), highchartOutput("wheel3", width = "100%", height = "400px"))
              
            ),
    ),
    
    tabItem(tabName = "donnee",
            dataTableOutput("table")
    ),
    
    tabItem(tabName = "analysedesc",
            fluidRow(
              column(6, 
                     h4("Top des IP source les plus émettrices", align="center"),
                     sliderInput("top1", "Top :", min = 1, max = 30, value = 5), 
                     highchartOutput("statdesc2")),
              column(6, 
                     h4("IP source non inclues dans le plan d'adressage", align="center"), 
                     sliderInput("top2", "Top :", min = 1, max = 30, value = 5), 
                     highchartOutput("wordcloud"))
            ),
            
            fluidRow(
              column(12, highchartOutput("wheel2", width = "100%", height = "600px")),
              column(12, DT::dataTableOutput("apercu_data2"))
            ),
    ),
    
    tabItem(tabName = "analysetemporelle",
            fluidRow(
              column(12, h3("Nombre d'actions en fonction du temps", align="center"), amChartsOutput(outputId = "plottime")),
              column(12, h3("Ports attaqués en fonction du temps", align="center"), amChartsOutput(outputId = "plottime2"))
            ),
        ),
    
    
    tabItem(tabName = "analyse",
          box(width = 8,
              plotlyOutput("Classement")),
          
          box(title="filtre", 
              width=4, 
              sliderInput("Top_n","Nombre de ports", min = 3,  max = 10,  value = 3),
              radioButtons("choix_top", "ipsrc, dstport",
                           choices = c("ipsrc", "dstport"), selected=c("ipsrc")),
              checkboxGroupInput("protocole", "Protocoles",choices = c("TCP","UDP"), selected = c("TCP","UDP")),
              radioButtons("choix_port", "Ports",choices = list("Tous les ports"="all","<= 1024" = "inf_1024", " > 1024" = "sup_1024"))
          )
        
    ),
    

    
    tabItem(tabName = "action",
            box(width = 8, title=" Action sur les ports RFC 6056",
                plotOutput("flux")
            ),
    
            box(title="Action", 
                width=4, 
                checkboxGroupInput("proto", "Protocoles",choices = c("TCP","UDP"), selected = c("TCP","UDP")),
                sliderInput("range", "Plage RFC",min = 0, max = 65535,value = c(1024,65535))
            ),
    ),
    
    tabItem(tabName = "udptcp",
            box(width = 8, title=" Classement des régles",
                plotlyOutput("rule")
            ),
            box(title="Plage", 
                width=4, 
                checkboxGroupInput("protoco", "Protocoles",choices = c("TCP","UDP"), selected = c("TCP","UDP")),
                checkboxGroupInput("actio", "Actions",choices = c("DENY","PERMIT"), selected = c("DENY","PERMIT"))
            )
    ),
    
    tabItem(tabName = "interactive",
            box(8, title = "visualisation interactive",
                plotOutput("vizinteract")),

            box(title="Filtre Index", 
                width=4, 
                sliderInput("plage", "Plage de données",min = 1, max = 500,value = 149)),
     ),
   
    tabItem(tabName = "universite",
            box(width = 8, title = "Nombre @IP hors zone université",
                plotlyOutput("univ")),
            
            box( width=4, 
                sliderTextInput("nb_univ", "Nombre @IP hors université ", c(3, 4, 5, 6, 7,8,9,10))),
    ),
    
    
    tabItem(tabName = "heure",
            box(width = 12, title = "Analuse de l'heure des attaques",
                plotOutput("heur"))
    ),

    tabItem(tabName="apprentissage",
                fluidRow(
                  column(4, selectInput("pos","Choisir Modalité positive",choices = unique(c("Choisir modalité positive","DENY","PERMIT")),selected = 'Choisir modalité positive')),
                  column(4,selectInput("algo","Algorithme",choices = c("Arbre de décision"),selected = 'Arbre de décision')),
                  column(4, sliderInput(inputId = "taille",label = "Taille apprentissage", value = 1000, min = 100, max = 5000, step=50)),
                  
                ),
            
            box(width = 12,
                fluidRow(
                  column(6, dataTableOutput("importance")),
                  column(6, plotOutput("plot_tree"))
                )
            )
    ),
    
    tabItem(tabName = "acm",
            box(width = 5,
                plotOutput("contrib")
            ),
            box(width = 5,
                plotOutput("acm")
            ),
            box(width=2, 
                radioButtons("color", "Habillage",choices = c("Action","Protocole")))
            
    )),
  
    
  useShinyjs()
)

#“blue”, “black”, “purple”, “green”, “red”, “yellow”
dashboardPage(header, sidebar, body, skin = "yellow")

