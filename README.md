# gatherd_and_mapper
This is a utility for gathering network inter-connectivity data on a small set of systems and saving in JSON format for building architecture data.

One key aspect of managing an Enterprise is understanding how everything is interconnected.  Without up to date design documentation understanding
architecture leads to business risk as changes to the Entrprise are not well identified.  gatherd was written to inventory the data for building 
a map of interconnectivity.  gatherd has been tested on a Linux platform and saves output in JSON format.

Future enhancements:
   - Add names (not just IP addresses) to help provide additional details in NAT'd or load balanced environments.
   - Add ability to weed out anything that may be an inbound "customer" connection.  For example, a web server may have tens of thousands of
     connections from outside IP space leading to nuisance data that does not help to define the architecture.  This could be handled via
     either command line arguments or a config file detailing the IP space to handle differently (no ignore, we want to know there may be
     thousands of inbound port 443 connections)l
   - Add forbidden ports to config file, for flagging.  Think insecure protocols like FTP or port 80 that a corporate policy may disallow.

The mapper utility was created as a validation tool as part of the POC of gatherd.  In reality data output from gatherd should be ingested by 
robust CMDB or architecture toolsets.  Think of an integration with an ITSM platform so that any change is aligned with impacts to other systems.
