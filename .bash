# Findomain -> Subdomain enumiration Tools
if [ -d "$HOME/.cargo/bin" ] ; then
    PATH="$HOME/.cargo/bin:$PATH"
fi


crtsh(){
curl -s https://crt.sh/?Identity=%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF'
}

certspotter(){ 
curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1
} #h/t Michiel Prins

rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
 | grep -oP '_blank">\K[^<]*' \
 | grep -v http \
 | sort -u
}

wayback(){
curl "https://web.archive.org/cdx/search/cdx?url=$1/*&output=text&fl=original&collapse=urlkey"
}
                                                                    
otx()
{
        gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$1?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq
}

gauq() {
        gau $1 -subs | \
        grep "=" | \
        egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | \
        qsreplace -a
}

sqliz() {
        gauq $1 | python3 $HOME/DSSS/dsss.py
}



bxss() {
        BLIND="https://your.xss.ht"
        gauq $1 | kxss | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | \
        dalfox pipe -b $BLIND
}



subdomain(){
        assetfinder -subs-only $1 | httprobe |\
        while read url;
        do
                hide=$(curl -s -L $url | egrep -o "('\")hidden('|\") name=('|\")[a-z_0-9-]*]" |\
                sed -e 's/\"hidden\"/[Found]/g' -e 's, 'name=\"','"$url"/?', g' |\
                sed 's/.*/&XssCheck/g');
                echo -e "\033[32m$url""\033[34m\n$hide";
        done
}

paramlist()
{
         waybackurls $1 |  grep "?" | unfurl keys  | sort -u |  tee -a paramlist.txt 
}

anyname(){
        echo "script is Running"
        #running nuclei scanner bu projectdiscovery
        cat $1 | nuclei -t templates/template

        echo "scanning for Xss"
        #scanning for xss using kxss by tomnomnom
        cat $1 | grep "=" | kxss
}

#subdomain takeover finding subdomain
subtakeover() {
subfinder -d $1 >> hosts | assetfinder -subs-only $1 >> hosts | amass enum -norecursive -noalts -d $1 >> hosts | subjack -w hosts -t 100 -timeout 30 -ssl -c ~/subjac>
}


