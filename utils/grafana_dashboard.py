#!/usr/bin/python3.6
import requests
import json
import copy
import os
import ipaddress


# LA DASHBOARD VIENE LETTA DAL TEMPLATE , MA LO STATO RIMANE IN MEMORIA DI ESECUZIONE (in un dizionario) E VIENE SCRITTO IN UN JSON IN FASE DI UPLOAD
class DashBoard:

    def __init__(self, apikey, refr):
        bootstrap = True

        self.token = apikey
        self.headers = {"Accept": "application/json",
                        "Content-Type": "application/json", "Authorization": self.token}

        print("Creating Dashboard")
        self.json = json.load(open('./template.json', "r"))
        self.json["refresh"] = refr + "s"

        data = {"dashboard": self.json, "overwrite": True}
        r = requests.post("http://localhost:3000/api/dashboards/db",
                          headers=self.headers, json=data)

        if r.status_code != 200:
            print("Grafana Error")
            print(r)
            exit(-1)

    def update_topin(self, in_sources):

        t_len = len(self.json["panels"][4]['targets'])
        s_len = len(in_sources)

        # new flow are less than saved , update and remove the rest
        if t_len > s_len:
            i = 0
            # Update
            while i < s_len:
                # Modify source
                self.json["panels"][4]['targets'][i]["target"] = "RRD_" + in_sources[i] + ":In"
                # Modify matcher
                self.json["panels"][4]['fieldConfig']['overrides'][i]['matcher']['options'] = ":RRD_" + in_sources[
                    i] + ":In"
                # Modify properties
                self.json["panels"][4]['fieldConfig']['overrides'][i]['properties'][0]['value'] = 'TOP' + str(
                    i + 1) + 'In:' + in_sources[i]
                i += 1

            # Remove the rest elements
            while i < t_len:
                self.json["panels"][4]['targets'].pop(-1)
                self.json["panels"][4]['fieldConfig']['overrides'].pop(-1)
                i += 1

        # new flow are move than saved , update and add the rest
        else:
            # Update
            i = 0
            while i < t_len:
                # Modify source
                self.json["panels"][4]['targets'][i]["target"] = "RRD_" + in_sources[i] + ":In"
                # Modify matcher
                self.json["panels"][4]['fieldConfig']['overrides'][i]['matcher']['options'] = ":RRD_" + in_sources[
                    i] + ":In"
                # Modify properties
                self.json["panels"][4]['fieldConfig']['overrides'][i]['properties'][0]['value'] = "TOP" + str(
                    i + 1) + "In:" + in_sources[i]

                i += 1

            # Add the rest
            while i < s_len:
                # Add source
                self.json["panels"][4]['targets'].append(
                    {"data": "", "refId": chr(i + 65), "target": "RRD_" + in_sources[i] + ":In", "type": "timeseries"})

                # Add tag and matcher
                override = {"matcher": {"id": "byName", "options": ":RRD_" + in_sources[i] + ":In"},
                            "properties": [{"id": "displayName", "value": "TOP" + str(i + 1) + "In:" + in_sources[i]}]}

                self.json["panels"][4]['fieldConfig']['overrides'].append(override)

                i += 1

    def update_topout(self, out_sources):

        t_len = len(self.json["panels"][6]['targets'])
        s_len = len(out_sources)

        # new flow are less than saved , update and remove the rest
        if t_len > s_len:
            i = 0
            # Update
            while i < s_len:
                # Modify source
                self.json["panels"][6]['targets'][i]["target"] = "RRD_" + out_sources[i] + ":Out"
                # Modify matcher
                self.json["panels"][6]['fieldConfig']['overrides'][i]['matcher']['options'] = ":RRD_" + out_sources[
                    i] + ":Out"
                # Modify properties
                self.json["panels"][6]['fieldConfig']['overrides'][i]['properties'][0]['value'] = 'TOP' + str(
                    i + 1) + 'Out:' + out_sources[i]
                i += 1

            # Remove the rest elements
            while i < t_len:
                self.json["panels"][6]['targets'].pop(-1)
                self.json["panels"][6]['fieldConfig']['overrides'].pop(-1)
                i += 1

        # new flow are move than saved , update and add the rest
        else:
            # Update
            i = 0
            while i < t_len:
                # Modify source
                self.json["panels"][6]['targets'][i]["target"] = "RRD_" + out_sources[i] + ":Out"
                # Modify matcher
                self.json["panels"][6]['fieldConfig']['overrides'][i]['matcher']['options'] = ":RRD_" + out_sources[
                    i] + ":Out"
                # Modify properties
                self.json["panels"][6]['fieldConfig']['overrides'][i]['properties'][0]['value'] = "TOP" + str(
                    i + 1) + "Out:" + out_sources[i]

                i += 1

            # Add the rest
            while i < s_len:
                # Add source
                self.json["panels"][6]['targets'].append(
                    {"data": "", "refId": chr(i + 65), "target": "RRD_" + out_sources[i] + ":Out",
                     "type": "timeseries"})

                # Add tag and matcher
                override = {"matcher": {"id": "byName", "options": ":RRD_" + out_sources[i] + ":Out"},
                            "properties": [
                                {"id": "displayName", "value": "TOP" + str(i + 1) + "Out:" + out_sources[i]}]}

                self.json["panels"][6]['fieldConfig']['overrides'].append(override)

                i += 1

    def update_topboth(self, both_sources):

        t_len = len(self.json["panels"][8]['targets'])
        s_len = len(both_sources)

        # new flow are less than saved , update and remove the rest
        if t_len > s_len:
            i = 0
            # Update
            while i < s_len:
                # Modify source
                self.json["panels"][8]['targets'][i]["target"] = "RRD_" + both_sources[i] + ":InOut"
                # Modify matcher
                self.json["panels"][8]['fieldConfig']['overrides'][i]['matcher']['options'] = ":RRD_" + both_sources[
                    i] + ":InOut"
                # Modify properties
                self.json["panels"][8]['fieldConfig']['overrides'][i]['properties'][0]['value'] = 'TOP' + str(
                    i + 1) + 'InOut:' + both_sources[i]
                i += 1

            # Remove the rest elements
            while i < t_len:
                self.json["panels"][8]['targets'].pop(-1)
                self.json["panels"][8]['fieldConfig']['overrides'].pop(-1)
                i += 1

        # new flow are move than saved , update and add the rest
        else:
            # Update
            i = 0
            while i < t_len:
                # Modify source
                self.json["panels"][8]['targets'][i]["target"] = "RRD_" + both_sources[i] + ":InOut"
                # Modify matcher
                self.json["panels"][8]['fieldConfig']['overrides'][i]['matcher']['options'] = ":RRD_" + both_sources[
                    i] + ":InOut"
                # Modify properties
                self.json["panels"][8]['fieldConfig']['overrides'][i]['properties'][0]['value'] = "TOP" + str(
                    i + 1) + "InOut:" + both_sources[i]

                i += 1

            # Add the rest
            while i < s_len:
                # Add source
                self.json["panels"][8]['targets'].append(
                    {"data": "", "refId": chr(i + 65), "target": "RRD_" + both_sources[i] + ":InOut",
                     "type": "timeseries"})

                # Add tag and matcher
                override = {"matcher": {"id": "byName", "options": ":RRD_" + both_sources[i] + ":InOut"},
                            "properties": [
                                {"id": "displayName", "value": "TOP" + str(i + 1) + "InOut:" + both_sources[i]}]}

                self.json["panels"][8]['fieldConfig']['overrides'].append(override)

                i += 1

    def addbound(self, json, source, p_index):

        i = len(self.json["panels"][p_index]['targets'])
        json["panels"][p_index]['targets'].append(
            {"data": "", "refId": chr(i + 65), "target": source, "type": "timeseries"})
        override = {"matcher": {"id": "byName", "options": ":"+source},
                    "properties": [{"id": "custom.lineStyle", "value": {"dash": [0, 10], "fill": "dot"}}]}
        json["panels"][p_index]['fieldConfig']['overrides'].append(override)

    def addstdev(self, json, source, p_index):

        json["panels"][p_index]['targets'].append(
            {"data": "", "refId": "upper", "target": source, "type": "timeseries"})
        override = {"matcher": {"id": "byName", "options": ":"+source},
                    "properties": [{"id": "custom.lineStyle", "value": {"dash": [0, 10], "fill": "dot"}},
                                   {"id": "custom.fillOpacity", "value": 10},
                                   {"id": "color", "value": {"fixedColor": "dark-red", "mode": "fixed"}}]}

        json["panels"][p_index]['fieldConfig']['overrides'].append(override)

    def upload_json(self, talkers):

        to_upload = copy.deepcopy(self.json)

        # Adding bounds

        self.addbound(to_upload, "Statistics:UpperBoundIn", 4)
        self.addbound(to_upload, "Statistics:LowerBoundIn", 4)
        self.addstdev(to_upload, "Statistics:StdDevIn", 4)

        self.addbound(to_upload, "Statistics:UpperBoundOut", 6)
        self.addbound(to_upload, "Statistics:LowerBoundOut", 6)
        self.addstdev(to_upload, "Statistics:StdDevOut", 6)

        self.addbound(to_upload, "Statistics:UpperBoundBoth", 8)
        self.addbound(to_upload, "Statistics:LowerBoundBoth", 8)
        self.addstdev(to_upload, "Statistics:StdDevBoth", 8)

        # Upload the log
        s = ""
        for t in talkers.keys():
            if not ipaddress.ip_address(talkers[t].ip).is_private:
                s += str(talkers[t]) + "\n\n"

        to_upload["panels"][2]["options"]["content"] = s

        with open('curr.json', "w") as jsonFile:
            json.dump(to_upload, jsonFile, indent=4)
        data = {"dashboard": to_upload, "overwrite": True}
        r = requests.post("http://localhost:3000/api/dashboards/db",
                          headers=self.headers, json=data)

        os.remove('curr.json')


if __name__ == '__main__':
    dash = DashBoard()
