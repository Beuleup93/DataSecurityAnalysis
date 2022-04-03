library(shiny)
library(shinyjs)
library(ggplot2)
library(RColorBrewer)
library(leaflet)
library(plotly)
library(ggthemes)
library(ggrepel)


source("source.R")

shinyServer(function(input, output, session) {
  
  getReactiveLog <- reactive({
    data <- getTypeData(type = input$dtype, limit = input$limit)
    return(data)
  })
  
  getReactiveACM <- reactive({
    acm = acm(getReactiveLog(), taille = input$limit)
    return(acm)
  })
  
  supervisedLearningReactive <- reactive({
    supervised_learning(getReactiveLog(), positive_mod=input$pos, taille = input$taille)
  })
  
  # red, yellow, aqua, blue, light-blue, green, navy, teal, olive, lime, orange, fuchsia, purple, maroon, black.
  # icons
  output$Item1 <- renderInfoBox({
    infoBox("Attaques", length(getReactiveLog()$id),
            icon = icon("calendar", lib = "font-awesome"),
            color = "yellow",
            fill = TRUE)
  })
  
  output$Item3 <- renderInfoBox({
    infoBox("IP",length(unique(getReactiveLog()$ipsrc)),
            icon = icon("user"),
            color = "yellow",
            fill = TRUE)
  })
  
  output$Item2 <- renderInfoBox({
    infoBox("Actions",length(unique(getReactiveLog()$action)),
            icon = icon("pie-chart"),
            color = "yellow",
            fill = TRUE)
  })
  
  output$table <- renderDataTable({
    getReactiveLog()
  })
  
  output$Classement <- renderPlotly({
    data <- getReactiveLog()
    if (input$choix_port == "all"){
      #tab = head(data,n=input$Top_n) %>% filter(proto %in% input$protocole) %>% arrange(desc(dstport)) 
      tab = head(n=input$Top_n,sort(table(subset(data,(data$proto %in% input$protocole), select=c(input$choix_top))),decreasing = TRUE))
      
    }else if(input$choix_port == "inf_1024"){
      #data_port = head(data,n=input$Top_n) %>% filter(proto %in% input$protocole) %>% filter(dstport <= 1024) %>% arrange(desc(dstport))
      tab =head(n=input$Top_n,sort(table(subset(data,(data$proto %in% input$protocole & data$dstport < 1024), select=c(input$choix_top))),decreasing = TRUE))
      
    }else if(input$choix_port =="sup_1024"){
      #data_port = head(data,n=input$Top_n) %>% filter(proto %in% input$protocole) %>% filter(dstport > 1024) %>% arrange(desc(dstport))  
      tab =head(n=input$Top_n,sort(table(subset(data,(data$proto %in% input$protocole & data$dstport >1024), select=c(input$choix_top))),decreasing = TRUE))
    }

    p <-ggplot(data = as.data.frame(tab), aes(x =factor(Var1), y=Freq)) +
      geom_bar(stat="identity", fill="lavender")+
      geom_text(aes(label=Freq), vjust=1.6, size=3)+
      theme_minimal()
    
    ggplotly(p)
  })
  
  output$flux <- renderPlot({
    data <- getReactiveLog()
    data = table(subset(data,(data$proto %in% input$proto & (data$dstport > input$range[1] & data$dstport<=input$range[2])), select=c("action")))
    
    data = as.data.frame(data) %>%
      arrange(desc(Freq)) %>%
      mutate(prop = percent(Freq / sum(Freq))) 

    pie_acc <- ggplot(data, aes(x = "", y = Freq, fill = fct_inorder(Var1))) +
      ggtitle("Action par protocole")+
      geom_bar(width = 1, stat = "identity") +
      coord_polar("y", start = 0) +
      geom_label_repel(aes(label = prop), size=5, show.legend = F, nudge_x = 1) +
      guides(fill = guide_legend(title = 'Action'))
    plot(pie_acc)
  })
  
  output$rule <- renderPlotly({
    data <- getReactiveLog()
    data = as.data.frame(table(subset(data,(data$proto %in% input$protoco & data$action %in% input$actio), select=c("policyid"))))
    p <- ggplot(data=data, aes(x=reorder(Var1,-Freq), y=Freq, fill = "#9885b2")) +
      geom_col()+
      ylab("count") +
      coord_flip() +
      theme_minimal() +
      ggtitle("") +
      ylab("Nombre de régles") +
      xlab("Régles") +
      geom_blank()+
      scale_fill_manual(values=c("#9885b2")) 
    ggplotly(p)
  })
  
  output$vizinteract <- renderPlot({
    data <- getReactiveLog()
    
    tab=as.matrix(table(data$ipsrc,data$action))
    w=data.frame(DENY = as.numeric(tab[,1]), as.numeric(tab[,2]))
    colnames(w) = c('DENY', 'PERMIT')
    rownames(w)=rownames(tab)
    IP_contact=w$DENY+w$PERMIT
    bdd=cbind(w,IP_contact)
    
    bd=bdd[1:input$plage,]
    index=1:input$plage
    bd=cbind(bd,index)
    
    ggplot(bd, aes(index, DENY)) + 
      geom_point(colour = "red", size = 1.5, shape=3)+ 
      labs(x = " ", y = "y1") + 
      geom_point(aes(index, PERMIT),size=1.5, colour="blue", shape=1)+
      geom_vline(xintercept=input$'plage', color = "green", size=1)
  })
  
  output$univ <- renderPlotly({
    dfIpUniv = getReactiveLog() %>%
      filter(!grepl("159.84.89.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])", ipsrc))
    
    portUnivCount = dfIpUniv %>%
      count(ipsrc, sort=TRUE) %>%
      arrange(desc(n)) %>%
      slice(seq_len(input$nb_univ))
    
    portUnivCount =as.data.frame(portUnivCount)
    p <-ggplot(data = portUnivCount, aes(x =factor(ipsrc), y=n)) +
      geom_bar(stat="identity", fill="#9885b2")+
      geom_text(aes(label=n), vjust=-0.3, size=3.5)+
      theme_minimal()
    ggplotly(p)
  })
  
  output$heur <- renderPlot({
    data <- getReactiveLog()
    hour_of_event <- hour(data$datetime)
    eventdata <- data.frame(datetime = data$datetime, eventhour = hour_of_event)
    eventdata$Horaire <- eventdata$eventhour %in% seq(7, 18)
    eventdata$Horaire[eventdata$Horaire =="TRUE"] <-"Horaires ouvrés"
    eventdata$Horaire[eventdata$Horaire =="FALSE"] <-"Horaires non ouvrés"
    
    ggplot(eventdata, aes(x = eventhour, fill = Horaire)) +
      geom_histogram(breaks = seq(0,24), colour = "grey") +
      coord_polar(start = 0) + theme_minimal() +scale_fill_brewer() + ylab("Somme") + ggtitle("Evenements par heure") +
      scale_x_continuous("", limits = c(0, 24),breaks = seq(0, 24), labels = seq(0, 24))
    
  })
  
  output$importance = renderDataTable({
    if(input$pos != 'Choisir modalité positive'){
        arbre = supervisedLearningReactive()
        dd = as.data.frame(arbre$variable.importance)
        dd$variable = rownames(dd)
        colnames(dd) = c("importance", "variable")
        dd
    }
  })
  
  output$plot_tree <- renderPlot({
    if(input$pos != 'Choisir modalité positive'){
        tree = supervisedLearningReactive()
        rpart.plot(tree)
    }
  })
  
  output$acm <- renderPlot({
    res.acm = getReactiveACM()
    if(input$color == "Action"){
      plot(res.acm, invisible = c("var","quali.sup"), habillage = "action" , title = "Graphe des modalités actives et illustratives")
    }else{
      plot(res.acm, invisible = c("var","quali.sup"), habillage = "proto" , title = "Graphe des modalités actives et illustratives")
    }
    
  })
  output$contrib <- renderPlot({
    res.acm = getReactiveACM()
    plot(res.acm, choix = "var", title = "Graphe des contributions variable")
  })
  
  output$statdesc2 <- renderHighchart({
    df <- getReactiveLog()
    df_ok = as.data.frame(sort(table(df$ipsrc), decreasing = TRUE))
    head(df_ok, 5)
    ClickFunction <- JS("function(event) {Shiny.onInputChange('Clicked', event.point.Var1);}")
    
    df_ok <- head(df_ok, input$top1)
    hchart(df_ok, "bar", hcaes(x = Var1, y = Freq), color = 'navyblue', name = "Fréquence d'apparition", pointWidth = 15) %>%
      hc_yAxis(title = list(text = "Mots")) %>%
      hc_xAxis(title = list(text = "Fréquence")) %>%
      hc_title(text = "Top des IP source les plus fréquentes") %>%
      hc_caption(text = "Ce diagramme peut être trié par région et par catégorie de métiers") %>%
      hc_add_theme(hc_theme_smpl()) %>%
      hc_plotOptions(series = list(events = list(click = ClickFunction)))
  })
  
  output$apercu_data2 <-  DT::renderDataTable({
    df <- getReactiveLog()
    df_drill <- df %>%
      filter(ipsrc %in% input$Clicked)
    
    DT::datatable(df_drill, filter = "top", option = list(pageLenght = 5, autoWidth = TRUE, lengthMenu = c(5, 10, 15, 20))) %>% 
      formatStyle('action', backgroundColor = styleEqual(c("Permit", "Deny"), c("#85C17E", "#DE2916"))) %>% 
      formatStyle('proto', backgroundColor = styleEqual(c("TCP", "UDP"), c("#FBF2B7", "#D0C07A")))
  })
  
  output$wordcloud <- renderHighchart({
    df <- getReactiveLog()
    adressage = rep("192.168.0.", 255)
    num = 1:255
    adressage_num = paste(adressage,num,sep="")
    
    df_ok = df[!df$ipsrc %in% adressage_num,] #%>% filter(ipsrc != adressage_num)
    df_ok_ok = as.data.frame(sort(table(df_ok$ipsrc), decreasing = TRUE))
    df_ok_ok <- head(df_ok_ok, input$top2)
    set.seed(0)
    
    ClickFunction <- JS("function(event) {Shiny.onInputChange('Clicked', event.point.Var1);}")
    
    hchart(df_ok_ok, "wordcloud", hcaes(name = Var1, weight = Freq), name = "Occurence") %>%
      hc_title(text = "IP source non inclues dans le plan d'adressage") %>%
      hc_add_theme(hc_theme_smpl()) %>%
      hc_plotOptions(
        series = list(events = list(click = ClickFunction)),
        dataLabels = list(enabled = TRUE,
                          format = "{point.Freq}"), 
        minFontSize = 10)
    
  })
  
  output$wheel2 <- renderHighchart({
    df <- getReactiveLog()
    
    dw <- df %>%
      select(ipsrc,dstport)
    
    dw$count <- 1
    dw <- aggregate(count ~ ., dw, FUN = sum)
    
    dw_ok_filter <- dw %>%
      filter(ipsrc %in% input$Clicked)
    
    names(dw_ok_filter)[names(dw_ok_filter) == 'ipsrc'] <- 'from'
    names(dw_ok_filter)[names(dw_ok_filter) == 'dstport'] <- 'to'
    names(dw_ok_filter)[names(dw_ok_filter) == 'count'] <- 'weight'
    
    
    highchart()%>%
      hc_add_series(data = dw_ok_filter,
                    name = "COOCCURENCES",
                    type = 'dependencywheel') %>%
      hc_title(text = "Ports atteints par cette adresse IP") %>%
      hc_add_theme(hc_theme_smpl()) %>%
      hc_chart(zoomType = "xy")
    
  })
  
  output$statdesc1 <- renderAmCharts({
    df <- getReactiveLog()
    df_ok = as.data.frame(table(df$action))
    colnames(df_ok) = c("label", "value")
    df_ok$color = c("#85C17E", "#DE2916")
    amPie(data = df_ok, inner_radius = 50, depth = 10, show_values = TRUE)
  })
  
  output$statdesc3 <- renderAmCharts({
    df <- getReactiveLog()
    df_ok = df %>% filter(dstport < 1024) %>% filter(action == "Permit")
    df_ok = as.data.frame(sort(table(df$dstport), decreasing = TRUE))
    amBarplot(x = "Var1", y = "Freq", data = head(df_ok, 10), depth = 15, labelRotation = -90)
  })
  
  
  output$wheel <- renderHighchart({
    df <- getReactiveLog()
    
    dw <- df %>%
      select(policyid,dstport)
    
    
    dw$count <- 1
    dw <- aggregate(count ~ ., dw, FUN = sum)
    dw_ok <- head(dw[order(dw$count, decreasing = TRUE),], 30)
    
    names(dw_ok)[names(dw_ok) == 'policyid'] <- 'from'
    names(dw_ok)[names(dw_ok) == 'dstport'] <- 'to'
    names(dw_ok)[names(dw_ok) == 'count'] <- 'weight'
    
    
    highchart()%>%
      hc_add_series(data = dw_ok,
                    name = "COOCCURENCES",
                    type = 'dependencywheel') %>%
      hc_add_theme(hc_theme_smpl()) %>%
      hc_chart(zoomType = "xy")
    
  })
  
  output$wheel3 <- renderHighchart({
    df <- getReactiveLog()
    
    dw <- df %>%
      select(policyid,action)
    
    
    dw$count <- 1
    dw <- aggregate(count ~ ., dw, FUN = sum)
    dw_ok <- head(dw[order(dw$count, decreasing = TRUE),], 30)
    
    names(dw_ok)[names(dw_ok) == 'policyid'] <- 'from'
    names(dw_ok)[names(dw_ok) == 'action'] <- 'to'
    names(dw_ok)[names(dw_ok) == 'count'] <- 'weight'
    
    
    highchart()%>%
      hc_add_series(data = dw_ok,
                    name = "COOCCURENCES",
                    type = 'dependencywheel') %>%
      hc_add_theme(hc_theme_smpl()) %>%
      hc_chart(zoomType = "xy")
    
  })
  
  # Time plot
  
  output$plottime <- renderAmCharts({
    df <- getReactiveLog()
    df$date = as.Date(df$datetime)
    df_ok <- df %>%
      select(date, action)
    
    df_ok <- df_ok %>%
      count(date, action)
    
    tab <- xtabs(n~date + action, data = df_ok)
    typeof(tab)
    tab <- as.data.frame.matrix(tab)
    tab$Date <- rownames(tab)
    rownames(tab) <- NULL
    tab$Date <- ymd_hms(tab$Date)
    amTimeSeries(tab, "Date", c("Deny", "Permit"))
    
  })
  
  output$plottime2 <- renderAmCharts({
    df <- getReactiveLog()
    df$date = as.Date(df$datetime)
    
    df_ok <- df %>%
      select(date, action)
    
    df_ok <- df %>%
      select(date, dstport)
    
    df_ok <- df_ok %>%
      count(date, dstport)
    
    tab <- xtabs(n~date + dstport, data = df_ok)
    typeof(tab)
    tab <- as.data.frame.matrix(tab)
    tab$Date <- rownames(tab)
    rownames(tab) <- NULL
    tab$Date <- ymd_hms(tab$Date)
    amTimeSeries(tab, "Date", c("22", "21", "80", "3306", "8080", "443", "445", "20", "23"))
    
  })
  

})

