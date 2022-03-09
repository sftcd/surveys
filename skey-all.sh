#!bin/bash


function whenisitagain()
{
	date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)

#startdir = `/bin/pwd`
echo "Running $0 at $NOW"


function usage()
{
	echo "$0 [-m] [-s <source-code-directory>] [-r <results-directory>] [-p <inter-dir>] [-c <country>] [-i <ips-src>] [-z <zmap-port>] [-k <skips>]"
	echo "	-m means do the maxmind thing"
	echo "	source-code-directory defaults to \$HOME/code/surveys"
	echo "	country must be IE or EE, default is IE"
	echo "	results-directory defaults to \$HOME/data/smtp/runs"
	echo "	inter-directory is a directory with intermediate results we process further"
	echo "	ips-src is a file with json lines like censys.io's (original censys.io input used if not supplied"
	echo "  zmap-port (default 25) is the port we use to decide what to scan"
	echo "	skips is a comma-sep list of stages to skip: mm,zmap,grab,fresh,cluster,graph"
	exit 99
}

srcdir=$HOME/code/surveys
outdir=$HOME/data/smtp/runs

country="IE"
ipssrc=''
pdir=''
domm='no'
dpath=`grep mmdbpath $HOME/code/surveys/SurveyFuncs.py  | head -1 | awk -F\' '{print $2}' | sed -e 's/\/$//'`
mmdbdir=$HOME/$dpath
zmport="25"
skips=""

if [[ "$zmap_parms" == "" ]]
then
	zmap_parms="-B 100K"
fi

if ! options=$(getopt -s bash -o ms:r:c:i:p:z:k:h -l mm,srcdir:,resdir:,country:,ips:,process:,zmap:,skips:,help -- "$@")
then
	# something went wrong, getopt will put out an error message for us
	exit 1
fi

eval set -- "$options"
while [ $# -gt 0 ]
do
	case "$1" in
		-h|--help) usage;;
		-m|--mm) domm="yes" ;;
		-s|--srcdir) srcdir="$2"; shift;;
		-z|--zmap) zmport="$2"; shift;;
		-r|--resdir) outdir="$2"; shift;;
		-k|--skips) skips="$2"; shift;;
		-i|--ips) ipssrc="$2"; shift;;
		-p|--process) pdir="$2"; shift;;
		-c|--country) country="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

if [ "$srcdir" == "" ]
then
	echo "No <code-directory> set"
	usage
fi

if [ ! -d $srcdir ]
then
	echo "$srcdir doesn't exist - exiting"
	usage
fi

if [ "$outdir" == "" ]
then
	echo "No <results-diretory> set"
	usage
fi

#check if country is known




echo "Starting at $NOW, log in $logf" 
echo "Starting at $NOW, log in $logf" >>$logf

# Variables to have set
unset SKIP_MM
unset SKIP_ZMAP
unset SKIP_GRAB
unset SKIP_FRESH
unset SKIP_CLUSTER
unset SKIP_GRAPH

# files uses as tell-tales
TELLTALE_MM="mm-ips."$country".v4"
TELLTALE_ZMAP="zmap.ips"
TELLTALE_GRAB="input.ips"
TELLTALE_FRESH="records.fresh"


echo "Starting Maxmind stuff"
python3 IPsFromMM.py -c $country

echo "starting zmap"
sudo zmap $zmap_parms -p $zmport -w $TELLTALE_MM -o TELLTALE_ZMAP
ln -s $TELLTALE_ZMAP $TELLTALE_GRAB
echo "zmap finished."

echo "starting grab"
python3 FreshGrab.py -i $TELLTALE_GRAB -o $TELLTALE_FRESH -c $country
echo "grabbed finished."
