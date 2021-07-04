from utils.talker import Talker
from utils.pipeline import Pipeline
from utils.init_functions import Setup
import ipaddress

import scapy
import datetime
import os
import traceback
from utils.grafana_dashboard import DashBoard
import rrdtool
from nfstream.streamer import NFStreamer
import operator
from concurrent.futures.thread import ThreadPoolExecutor
import configparser
from scapy.sendrecv import  sniff
from scapy.utils import PcapWriter

# Remove warnings for scrapy
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def producer(pl, chosen_if, rrd_step):
    try:
        print("producer is active")

        # Formato di display della data
        p = '%Y-%m-%d--%H:%M:%S'

        while True:

            pktdump = PcapWriter("temp.pcap")

            for pkt in sniff(iface=chosen_if, timeout=int(rrd_step)):
                pktdump.write(pkt)

            # tcpdump alcune volte non ci mette 10 sec , quindi è necessario calcolare il tempo di fine effettivo
            finish_date = datetime.datetime.now()

            # ottengo la data
            timestring = finish_date.strftime(p)

            # setto la data come nome per il file
            f_name = timestring + ".pcap"

            os.rename('temp.pcap', f_name)

            # rinomina
            pl.set_message(finish_date.timestamp(), "Producer")

    except Exception as e:
        print(e)
        traceback.print_exc()


def consumer(pl, grafana_api, rrd_step, ttl, rk_tim, max_top, filter_mode):
    try:
        # Define parameters for RRD
        hb = str(int(rrd_step) * 3)
        min_rrd_value = "0"
        max_rrd_value = "U"
        p = '%Y-%m-%d--%H:%M:%S'

        # Creating Grafana dashboard
        db = DashBoard(grafana_api, rrd_step)

        # Structure that will contain all talkers data
        talkers = {}

        # Lists that contain top3 of every metric
        last_sort_in = []
        last_sort_out = []
        last_sort_both = []

        # l'rrd contiene caselle per i dati fino a adesso - step
        creationtimestring = 'now-' + str(int(rrd_step) + 1) + 's'

        # Metadata+StdDev_Stats RRD
        rrdtool.create("./rrd/Statistics.rrd", '--start', creationtimestring,
                       '--step', rrd_step, 'RRA:AVERAGE:0.5:1:1000',
                       'DS:In:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:Out:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:N_Flow:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),

                       'DS:MeanIn:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:MeanOut:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:MeanBoth:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),

                       'DS:VarianceIn:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:VarianceOut:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:VarianceBoth:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),

                       'DS:StdDevIn:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:StdDevOut:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:StdDevBoth:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),

                       'DS:UpperBoundIn:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:LowerBoundIn:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:UpperBoundOut:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:LowerBoundOut:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:UpperBoundBoth:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value),
                       'DS:LowerBoundBoth:GAUGE:{}:{}:{}'.format(hb, min_rrd_value, max_rrd_value)
                       )

        first_cycle = True

        while True:

            # ---------------------------------------------------------#
            #          FIRST PHASE: Preparing data from pcap          #
            # ---------------------------------------------------------#

            # Reset Period/Cycle variables
            if first_cycle or rk_tim:
                i = 0
                period_nflow = 0
                period_in = 0
                period_out = 0
                period_both = 0

                for talker in talkers.values():
                    talker.ResetTotalPeriodCounter()

            cycle_in_sum = 0
            cycle_out_sum = 0
            cycle_both_sum = 0
            cycle_nflow = 0

            # Reconstruct the file name
            ts = pl.get_message("Producer")
            timestring = datetime.datetime.fromtimestamp(ts).strftime(p)
            f_name = timestring + '.pcap'
            print("nuovo file generato , aggiorno\n\n\n")

            flow_streamer = NFStreamer(source=f_name, statistical_analysis=True, promiscuous_mode=True,
                                       accounting_mode=0)
            # Studying flows , if it's a new flow create the structure and rdd o/w update it
            for flow in flow_streamer:

                print(flow.application_name + " -> " + flow.src_ip + " -> " + flow.dst_ip + "[" + str(
                    flow.src2dst_bytes) + "] " \
                      + flow.dst_ip + " -> " + flow.src_ip + "[" + str(flow.dst2src_bytes) + "]")

                if filter_mode == "ip":  # Every flow is identified by external ip
                    if ipaddress.ip_address(flow.dst_ip).is_private:  # src is an external talker
                        if flow.src_ip not in talkers.keys():
                            # create talker structure
                            curr_talker = Talker(flow.src_ip, flow.application_name, flow.dst2src_bytes,
                                                 flow.src2dst_bytes, "ip"
                                                 , flow.application_category_name, flow.application_is_guessed,
                                                 flow.requested_server_name, flow.client_fingerprint,
                                                 flow.server_fingerprint,
                                                 flow.user_agent, flow.content_type)

                            # create his RRD
                            curr_talker.RRDcreate(rrd_step, hb, min_rrd_value, max_rrd_value, creationtimestring)
                            # insert in talkers
                            talkers[flow.src_ip] = curr_talker
                            # new flow -> increase period flow counter
                            period_nflow += 1
                        else:
                            talkers[flow.src_ip].update(ts, flow.dst2src_bytes, flow.src2dst_bytes)

                    else:  # dst is an external talker

                        if flow.dst_ip not in talkers.keys():
                            # create talker structure
                            curr_talker = Talker(flow.dst_ip, flow.application_name, flow.src2dst_bytes,
                                                 flow.dst2src_bytes, "ip"
                                                 , flow.application_category_name, flow.application_is_guessed,
                                                 flow.requested_server_name, flow.client_fingerprint,
                                                 flow.server_fingerprint,
                                                 flow.user_agent, flow.content_type)

                            # create his RRD
                            curr_talker.RRDcreate(rrd_step, hb, min_rrd_value, max_rrd_value, creationtimestring)
                            # insert in talkers
                            talkers[flow.dst_ip] = curr_talker
                            # new flow -> increase period flow counter
                            period_nflow += 1
                        else:
                            talkers[flow.dst_ip].update(ts, flow.src2dst_bytes, flow.dst2src_bytes)

                ###################################################################################
                elif filter_mode == "prot7":

                    if flow.application_name not in talkers.keys():

                        if ipaddress.ip_address(flow.src_ip).is_private:  # flow localhost -> talker
                            # create talker structure
                            curr_talker = Talker(flow.dst_ip, flow.application_name, flow.src2dst_bytes,
                                                 flow.dst2src_bytes, "prot7"
                                                 , flow.application_category_name, flow.application_is_guessed,
                                                 flow.requested_server_name, flow.client_fingerprint,
                                                 flow.server_fingerprint,
                                                 flow.user_agent, flow.content_type)

                        else:  # flow talker -> localhost
                            # create talker structure
                            curr_talker = Talker(flow.dst_ip, flow.application_name, flow.dst2src_bytes,
                                                 flow.src2dst_bytes, "prot7"
                                                 , flow.application_category_name, flow.application_is_guessed,
                                                 flow.requested_server_name, flow.client_fingerprint,
                                                 flow.server_fingerprint,
                                                 flow.user_agent, flow.content_type)

                        # create his RRD
                        curr_talker.RRDcreate(rrd_step, hb, min_rrd_value, max_rrd_value, creationtimestring)
                        # insert in talkers
                        talkers[flow.application_name] = curr_talker
                        # new flow -> increase period flow counter
                        period_nflow += 1

                    else:

                        if ipaddress.ip_address(flow.src_ip).is_private:
                            talkers[flow.application_name].update(ts, flow.src2dst_bytes, flow.dst2src_bytes)
                        else:
                            talkers[flow.application_name].update(ts, flow.dst2src_bytes, flow.src2dst_bytes)

                else:
                    exit(-1)

            # remove pcap
            os.remove(f_name)

            # -------------------------------------------------------------------#
            #     SECOND PHASE: Aggregate flows data and removing old flows     #
            # -------------------------------------------------------------------#

            # Removing old flows / update the rest
            for talker in list(talkers.values()):

                # If flow has not been updated in the last ttl seconds , remove it
                if talker.lastupdate is not None and talker.lastupdate + ttl <= ts:

                    if filter_mode == "ip":
                        curr = talkers.pop(talker.ip)

                    elif filter_mode == "prot7":
                        curr = talkers.pop(talker.prot7)

                    curr.RRDdeletion()

                # o/w consider it for the std_dev calculation
                else:
                    cycle_in_sum += talker.in_bytes_current
                    cycle_out_sum += talker.out_bytes_current
                    cycle_both_sum += talker.inandout_bytes_current
                    period_nflow += 1

            period_in += cycle_in_sum
            period_out += cycle_out_sum
            period_both += cycle_both_sum

            # Check if data is enough
            if period_nflow > 0 and len(talkers) > 0:

                # -------------------------------------------------------------------#
                #             THIRD PHASE: Standard Dev Calculating                 #
                # -------------------------------------------------------------------#

                mean_in = period_in / period_nflow
                mean_out = period_out / period_nflow
                mean_both = period_both / period_nflow

                # Calculating variance of every metric
                variance_in = 0
                variance_out = 0
                variance_both = 0

                for talker in talkers.values():

                    variance_in += pow(talker.in_bytes - mean_in, 2)
                    variance_out += pow(talker.out_bytes - mean_out, 2)
                    variance_both += pow(talker.inandout_bytes - mean_both, 2)

                    # Update total counter and reset current
                    talker.RRDupdate(ts)
                    talker.ResetCurrentCounter()

                    # Little dump to read data manualy and check
                    if filter_mode == "ip":
                        rrdtool.dump("./rrd/RRD_" + talker.ip + ".rrd",
                                     "./xml/" + talker.ip + ".xml")

                    elif filter_mode == "prot7":
                        rrdtool.dump("./rrd/RRD_" + talker.prot7 + ".rrd",
                                     "./xml/" + talker.prot7 + ".xml")

                # Calculating Standard Deviation of every metric
                stdev_in = pow(variance_in / period_nflow, 1 / 2)
                stdev_out = pow(variance_out / period_nflow, 1 / 2)
                stdev_both = pow(variance_both / period_nflow, 1 / 2)

            # -------------------------------------------------------------------#
            #            FOURTH PHASE: Updating RRD and GRAFANA                 #
            # -------------------------------------------------------------------#

            upperbound_in = mean_in + stdev_in
            upperbound_out = mean_out + stdev_out
            upperbound_both = mean_both + stdev_both

            lowerbound_in = mean_in - stdev_in
            if lowerbound_in < 0: lowerbound_in = 0

            lowerbound_out = mean_out - stdev_out
            if lowerbound_out < 0: lowerbound_out = 0

            lowerbound_both = mean_both - stdev_both
            if lowerbound_both < 0: lowerbound_both = 0

            rrdtool.update("./rrd/Statistics.rrd",
                           f'{ts}' + ':' + str(period_in) + ':' + str(period_out) + ':' + str(int(period_nflow)) + ':'
                           + str(mean_in) + ':' + str(mean_out) + ':' + str(mean_both) + ':'
                           + str(variance_in) + ':' + str(variance_out) + ':' + str(variance_both) + ':'
                           + str(stdev_in) + ':' + str(stdev_out) + ':' + str(stdev_both) + ':'
                           + str(upperbound_in) + ':' + str(lowerbound_in) + ":"
                           + str(upperbound_out) + ':' + str(lowerbound_out) + ":"
                           + str(upperbound_both) + ':' + str(lowerbound_both))

            if len(talkers) > 0:

                change = False

                t_sorted = sorted(talkers.values(), key=operator.attrgetter('in_bytes'), reverse=True)

                if last_sort_in != t_sorted:

                    if filter_mode == "ip":
                        strings = [t.ip for t in t_sorted]
                    elif filter_mode == "prot7":
                        strings = [t.prot7 for t in t_sorted]

                    db.update_topin(strings[:max_top])
                    last_sort_in = t_sorted
                    change = True

                t_sorted = sorted(talkers.values(), key=operator.attrgetter('out_bytes'), reverse=True)

                if last_sort_out != t_sorted:

                    if filter_mode == "ip":
                        strings = [t.ip for t in t_sorted]
                    elif filter_mode == "prot7":
                        strings = [t.prot7 for t in t_sorted]

                    db.update_topout(strings[:max_top])
                    last_sort_out = t_sorted
                    change = True

                t_sorted = sorted(talkers.values(), key=operator.attrgetter('inandout_bytes'), reverse=True)

                if last_sort_both != t_sorted:

                    if filter_mode == "ip":
                        strings = [t.ip for t in t_sorted]
                    elif filter_mode == "prot7":
                        strings = [t.prot7 for t in t_sorted]

                    db.update_topboth(strings[:max_top])
                    last_sort_both = t_sorted
                    change = True

                if change is True:
                    db.upload_json(talkers)

                i += 1

    except Exception as e:
        print(e)
        traceback.print_exc()


if __name__ == '__main__':
    Setup()

    # Get settings from config.ini
    conf = configparser.ConfigParser()

    conf.read("config.ini")
    interface = conf.get("Settings", "interface")
    grafana_api = conf.get("Settings", "grafana_api")
    filter_mode = conf.get("Settings", "filter_mode")
    rrd_step = conf.get("Settings", "refresh")
    ttl = conf.get("Settings", "ttl_flow")
    rk_tim = conf.get("Settings", "refr_ranking")
    max_top = conf.get("Settings", "max_top")

    print("Do you want me to start grafana-rrd-server plugin?")

    while True:
        answer = input("[y/n] ")
        if answer == "y":
            done = False
            # Close any process on port 9000
            os.system("sudo fuser -k 9000/tcp")

            # Start Grafana
            try:

                os.system("sudo ~/go/bin/grafana-rrd-server -r ./rrd -s " + rrd_step + " &")
                done = True
            except:
                print("grafana-rrd-server is not in the default directory")
                if not done:
                    try:
                        os.system("sudo ./grafana-rrd-server -r ./rrd -s " + rrd_step + " &")
                    except:
                        print("grafana-rrd-server is not in the current program directory")
            break

        elif answer == "n":
            print("Be sure to start grafana-rrd-server by yourself")
            break

    # Start software
    executor = ThreadPoolExecutor(max_workers=2)
    pl = Pipeline()
    executor.submit(producer, pl, interface, rrd_step)
    executor.submit(consumer, pl, grafana_api, rrd_step, int(ttl), int(rk_tim), int(max_top), filter_mode)
