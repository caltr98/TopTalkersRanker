# TopTalkersRanker
Gestione Di Reti 20/21 Progetto Finale Turco-Ziccolella

* Classifica dei primi X top talkers per Ip o classifica dei Protocolli di livello 7 più utilizzati 

### Dipendenze Python:
* scapy
* nfstream

### Requisiti per l'esecuzione:

* [rrd-tool](https://oss.oetiker.ch/rrdtool/download.en.html)

* [grafana-rrd-server](https://github.com/doublemarket/grafana-rrd-server)

* [Grafana](https://grafana.com/docs/grafana/latest/installation/debian/)

* [JSON API Grafana Datasource](https://grafana.com/grafana/plugins/simpod-json-datasource/)

* Python 3.x


Per eseguire il programma:

sudo python3 appy.py

Per arrestare il programma:

ctrl + Z

## Configurazione :
  1. Inserire come DataSource grafana-rrd-server porta di default 9000![image](https://user-images.githubusercontent.com/49340033/124386911-e05c6700-dcdc-11eb-861c-aa7487f499b5.png)

  2. Opzionale: Avvio da linea di comando di grafana-rrd-server -s [stepRRD] -p [porta] -r [directory files .rrd]
  3. Creazione Api Key di Grafana ![image](https://user-images.githubusercontent.com/49340033/124387161-b6f00b00-dcdd-11eb-969a-83f36b66d624.png)

  4. sudo python3 appy.py
  5. Creazione nuova config
      1. Scelta interfaccia cattura
      2. inserimento Api Grafana [Bearer --------] 
      3. Scelta modalità di aggregazione ip/prot7
      4. Scelta RRD step sec
      5. Scelta secondi entro il quale talker deve fare traffico per non essere eliminato
      6. Scelta nel numero di cicli (RDD step sec * Numero di cicli) in cui aggiornare la classifica nella dashboard
      7. Scelta numero di talkers da esporrè nei grafici in classifica
      8. Scelta se avviare da programma grafana-rrd-server
  7. Avvio di grafana-rrd-server
  
  ## Esecuzione:
  Modalità di aggregazione
  * ip
  ![image](https://user-images.githubusercontent.com/49340033/124388049-39c69500-dce1-11eb-946b-2b78f253877f.png)

  * prot7
  
  ![image](https://user-images.githubusercontent.com/49340033/124387379-abe9aa80-dcde-11eb-87a8-1b4d5ce86c03.png)
