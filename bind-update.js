"use strict";

var https = require ('https');
var fs = require('fs');
var path = require('path');
var readline = require('readline');
var os = require('os');

const CONFIG = "./config.json";
const CACHEDIR = "/tmp/dns-hole";

class Config {
   
    constructor() {
        this.sources = null;
    }
    

    checkExists() {
        try {
            if (fs.existsSync(CONFIG)) 
                return true;
        } catch (e) {
            return false;
        }
    }

    read() {
        
        console.log('* Reading block sites list');
        
        if (this.checkExists()) {
            try {
                return JSON.parse(fs.readFileSync(CONFIG));
            } catch (e) {
                return null;
            }
        } else
            return null;
    }
};


class Downloader {
   
    constructor(sources) {
        this.sources = sources;
    }

    getCacheDir() {
        // note: this is only build for *nix, so /tmp is the only hc return
        
        try {
            if (!fs.existsSync(CACHEDIR))
                fs.mkdirSync(CACHEDIR);
            return CACHEDIR;
        } catch (e) {
            return null;
        }
    }

    download(url, name, dir) {
        
        return new Promise((resolve, reject) => {
           
            var returnValue = {result: true, msg: null};

            const dest = dir+'/'+name+'.txt';
            const file = fs.createWriteStream(dest);

            console.log('  => Downloading '+url);

            const request = https.get(url, (response) => {
                // check if response is success
                if (response.statusCode !== 200) {
                    returnValue.result = false;
                    returnValue.msg = 'Server returned '+response.statusCode+' when downloading '+url;
                    reject(returnValue);
                } 
                response.pipe(file);
            });

            file.on('finish', () => {
                file.close();
                returnValue.result = true;
                returnValue.msg = "Success";
                returnValue.file = dest;
                resolve(returnValue);
            });

            request.on('error', (err) => {
                fs.unlink(dest);
                returnValue.result = false;
                returnValue.msg = 'Server returned '+err.message+' when downloading '+url;
                resolve(returnValue);
            });

            file.on('error', (err) => {
                fs.unlink(dest); // Delete the file async. (But we don't check the result) 
                returnValue.result = false;
                returnValue.msg = 'Error writing file '+dest+': '+err.message;
                reject(returnValue);

            });

        });

    }


    isRemote(url) {
        let newUrl = url.toLowerCase();
        return newUrl.indexOf('https')==0;
    }

    copyLocalFile(fileName) {
        console.log('  => Copying local file '+fileName); 
        var returnValue = null;
        if (fs.existsSync(fileName)) 
            try {
                let baseName = path.basename(fileName);
                fs.copyFileSync(fileName, CACHEDIR+'/'+baseName);
                returnValue = baseName;
            } catch (e) {
                // let it fall through 
            }
        return returnValue;
    }
    // returns a 1-dim array of paths
    async execute() {
        
        var returnValue = [];

        let cacheDir = this.getCacheDir();
        if (cacheDir === null)
            return null;


        for (var i=0; i<this.sources.length; i++) {
            try { 
                
                // this is a remote file; only https is supported
                if (this.isRemote(this.sources[i].url)) {
                    const resp = await this.download(
                        this.sources[i].url, this.sources[i].name, cacheDir);
            
                    if (resp.result)
                        returnValue.push(
                         {file: resp.file, format: this.sources[i].format}
                        );
                } 
                // others or local file
                else {
                    const fileName = this.copyLocalFile(this.sources[i].url);
                    if (fileName)
                        returnValue.push(
                         {file: fileName, format: this.sources[i].format}
                        );
                }
            } catch (e) {
                console.log("  x "+e.msg);
            }
        }

        return returnValue;
    }
}

class FileProcessor {

    constructor(fileList) {
        this.fileList = fileList;
        this.entryList = [];
    }

    checkValidDNSEntry(dns) {
        const pattern = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/g;
        return pattern.test(String(dns));
    }

    async processFile(filename, format) {
        return new Promise((resolve, reject) => {
            var that = this;

            try {

                if (!fs.existsSync(filename)) {
                    resolve(null);
                    return;
                }
                
                const r1 = readline.createInterface({
                    input: fs.createReadStream(filename),
                    terminal: false
                }); 
              


                var result = [];

                r1.on('line', line => {
                    
                    // replace multiple spaces with one
                    line = line.replace(/ +(?= )/g,'');
                    // tokenzie
                    var tokens = line.split(' ');
                    // only look at tokens that meet criteria

                    if (tokens.length > 0 && tokens[0][0] !== '#') {

                        let dnsEntry = "";

                        switch (format) {
                            
                            case "two-col": 
                                if (tokens.length > 1)
                                    dnsEntry = tokens[1].toLowerCase().trim();
                            break;

                            case "one-col": 
                                dnsEntry = tokens[0].toLowerCase().trim();
                            break;
                            
                            case "dnsmasq":
                                let masqSplit = tokens[0].split('/');
                                if (masqSplit.length > 1)
                                    dnsEntry = masqSplit[1].toLowerCase().trim();
                            break;
                        }

                        if (dnsEntry !== 'localhost' && dnsEntry !== "" 
                                && that.checkValidDNSEntry(dnsEntry))
                            result.push(dnsEntry);

                    }
                }); 

                r1.on('close', () => {
                    resolve(result);
                });

                r1.on('error', () => {
                    resolve(null);
                });


            } catch (e) {
                resolve(null);
            }

        });
    }

    async analyzeFiles() {

        var parseLines = [];

        console.log('* Analyzing '+this.fileList.length+' DNS hole files');
        
        for (var i=0; i<this.fileList.length; i++) {
            
            let entry = this.fileList[i];
            let newParseLines = await this.processFile(entry.file, entry.format);

            if (newParseLines != null) {
                console.log('  + Found '+newParseLines.length+' DNS entries in '+entry.file);
                parseLines = [...parseLines, ...newParseLines];
            } else
                console.log('  x Error processing '+entry.file+' with '+entry.format+' format');
        }
      
        let initCount = parseLines.length;
        parseLines = [...new Set(parseLines)]; // remove dupes 
        let dupeCount = (initCount-parseLines.length)/initCount*100;
        
        console.log('* Added a total of '+parseLines.length+' entries ('+dupeCount.toFixed(1)+'% duplicate)');
        
        return parseLines;
    }
}

class ZoneFileWriter {
    
    constructor(entries, filename, blockedZone, outputType) {
        this.entries = entries;
        this.filename = filename;
        this.blockedZone = blockedZone;
        this.outputType = outputType;
    }

    getRPZHdr() {
        return "$TTL 86400"+os.EOL+
               "@ IN SOA ns1.example.com. root.example.com. (2020071001 3600 1800 604800 86400)"+os.EOL+
               "@ IN NS  ns1.example.com. ;"+os.EOL;
    }

    async write() {
        
        console.log('* Writing entries to '+this.filename+' as zone type "'+this.outputType+'"');
        
        return new Promise((resolve, reject) => {
            try {
                let writeStream = fs.createWriteStream(this.filename);
                
                switch (this.outputType) {
                    case "dns":
                        this.entries.forEach(value => writeStream.write(
                            'zone "'+value+'" { type master; file "'+this.blockedZone+'"; };'+os.EOL));
                        break;
                    case "rpz":
                        writeStream.write(this.getRPZHdr());
                        this.entries.forEach(value => writeStream.write(
                            value+' CNAME .'+os.EOL));
                        break;
                }

                writeStream.end();

                writeStream.on('finish', () => {
                    console.log('* Saved file');
                    resolve(true);
                });

                writeStream.on('error', (err) => {
                    resolve(false);
                    console.log(' ERROR ');
                });

            } catch (e) {
                console.log(' x Error writing to '+this.filename);
                resolve(false);
            }
        });
    }
}

class App {
   
    constructor() {
        this.settings = null;
    }

    abort(msg) {
        console.log(' x ERROR: '+msg, 'Aborting..');
        process.exit(1);
    }

    async run() {
        console.log('DNS-Hole Processor');       
        
        let config = new Config();
        this.settings = config.read(); 

        if (this.settings === null)
            this.abort('Missing or corrupt config file: '+CONFIG);
        
        let dl = new Downloader(this.settings.sources);
        const fileList = await dl.execute(); 
        
        // this is for programming purposes only - cached
        /*var fileList = [
            { file: '/tmp/dns-hole/Badd-Boyz-Hosts.txt', format: 'two-col' },
            { file: '/tmp/dns-hole/KADhosts.txt', format: 'two-col' },
            { file: '/tmp/dns-hole/Malware-Download-List.txt', format: 'two-col'},
            { file: '/tmp/dns-hole/Notracking-hosts-GITHub.txt', format: 'two-col'},
            { file: '/tmp/dns-hole/Notracking-domains-GITHub.txt', format: 'dnsmasq'}
        ];*/

        if (fileList===null) {
            this.abort('Cannot create or access the cache dir: '+CACHEDIR);
        }

        let proc = new FileProcessor(fileList);
        let dnsEntries = await proc.analyzeFiles();
        

        let zoneFile = new ZoneFileWriter(dnsEntries, 
             CACHEDIR+'/'+this.settings.blackListZoneDB,
             this.settings.bindConfigDir+'/'+this.settings.blockedZone,
            this.settings.zoneFileType);
        await zoneFile.write();
    }


};

let app = new App();
app.run().then((result) => {
    console.log('Success');
    if (result != null) 
        console.log(result);
  }).catch((error) => {
    console.error('FATAL');
    console.error(error);
    process.exit(1);
});
