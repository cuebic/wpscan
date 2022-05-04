#!/bin/bash

set -e -o pipefail

SCRIPT_NAME=$(dir ${0})
WPSCAN_API_KEY=${1}
CVE_URL="https://services.nvd.nist.gov/rest/json/cve/1.0"
WPSCAN_URL="https://wpscan.com/api/v3"
OUTDIR="output"

if [[ ${WPSCAN_API_KEY} == "" ]]; then
  echo "Require WPSCAN API KEY!"
  exit 1
fi

##############################
## mainwp medias.tsv
##############################
echo -e "wpid\tname\turl" >${OUTDIR}/medias.tsv
mysql mainwp-prd -B -N -e 'select id, name, url from wp_mainwp_wp' >>${OUTDIR}/medias.tsv

##############################
## mainwp cores.tsv
##############################
echo -e "wpid\twp_version" >${OUTDIR}/cores.tsv
mysql mainwp-prd -B -N -e 'select wpid, value from wp_mainwp_wp_options where name="last_wp_upgrades" order by wpid' |
  while IFS=$'\t' read wpid option; do
    version=$(echo ${option} | jq -r 'select(.current? | length > 0) | .current')
    if [[ ${version} == "" ]]; then
      version="nodata"
    fi
    echo -e "${wpid}\t${version}" >>${OUTDIR}/cores.tsv
  done

##############################
# wpscan core_vuls.tsv
##############################
if [[ -f wpscan_wordpresses_api.result ]]; then
  rm -f ${OUTDIR}/wpscan_wordpresses_api.result
fi
cat ${OUTDIR}/cores.tsv | awk -F"\t" '{ print $2 }' | sed -e '1d' -e '/nodata/d' | sort | uniq >${OUTDIR}/core.list
cat ${OUTDIR}/core.list | while read version; do
  format_version=$(echo ${version} | sed 's/\.//g')
  curl -s -H "Authorization: Token token=${WPSCAN_API_KEY}" ${WPSCAN_URL}/wordpresses/${format_version} |
    sed 's/\\\u\(....\)/\&#x\1;/g' | nkf --numchar-input -w | jq -c >>${OUTDIR}/wpscan_wordpresses_api.result
done
echo -e "version\tfixed_in\ttitle" >${OUTDIR}/core_vuls.tsv
cat ${OUTDIR}/wpscan_wordpresses_api.result | while read -r line; do
  version=$(echo ${line} | jq -rs '.[] | keys[]')
  echo ${line} | jq .\"${version}\" | jq -r 'select(.vulnerabilities? | length > 0) | .vulnerabilities[] | [.title, .fixed_in] | @tsv' |
    while IFS=$'\t' read -r title fixedin; do
      echo -e "${version}\t${fixedin}\t${title}" >>${OUTDIR}/core_vuls.tsv
    done
done

##############################
## mainwp plugins.tsv
##############################
echo -e "wpid\tslug\tversion" >${OUTDIR}/plugins.tsv
mysql mainwp-prd -B -N -r -e 'select id, plugins from wp_mainwp_wp order by id' |
  while IFS=$'\t' read -r wpid plugins_json; do
    echo ${plugins_json} | jq -r '.[] | [(.slug | split("/") | .[0]), .version] | @tsv' |
      while IFS=$'\t' read -r slug version; do
        echo -e "${wpid}\t${slug}\t${version}" >>${OUTDIR}/plugins.tsv
      done
  done

##############################
# wpscan plugin_vuls.tsv
##############################
if [[ -f wpscan_plugins_api.result ]]; then
  rm -f ${OUTDIR}/wpscan_plugins_api.result
fi
cat ${OUTDIR}/plugins.tsv | awk -F"\t" '{ print $2 }' | sed -e '1d' -e '/nodata/d' | sort | uniq >${OUTDIR}/plugin.list
cat ${OUTDIR}/plugin.list | while read slug; do
  echo ${slug}
  curl -s -H "Authorization: Token token=${WPSCAN_API_KEY}" ${WPSCAN_URL}/plugins/${slug} |
    sed 's/\\\u\(....\)/\&#x\1;/g' | nkf --numchar-input -w | jq -c >>${OUTDIR}/wpscan_plugins_api.result
done
echo -e "slug\tlatest\tfixed_in\ttitle\tcve_id" >${OUTDIR}/plugin_vuls.tsv
cat ${OUTDIR}/wpscan_plugins_api.result | while read -r line; do
  slug=$(echo ${line} | jq -rs '.[] | keys[]')
  friendly_name=$(echo ${line} | jq .\"${slug}\" | jq 'select(.friendly_name? | length > 0) | .friendly_name')
  if [[ ${friendly_name} == "" ]]; then
    continue
  fi
  latest=$(echo ${line} | jq .\"${slug}\" | jq -r 'select(.latest_version? | length > 0) | .latest_version')
  if [[ ${latest} == "null" ]]; then
    latest="nodata"
  fi
  vuls=$(echo ${line} | jq .\"${slug}\" | jq -rc 'select(.vulnerabilities? | length > 0) | .vulnerabilities')
  if [[ ${vuls} = "" ]]; then
    echo -e "${slug}\t${latest}\tnodata\tnodata\tnodata" >>${OUTDIR}/plugin_vuls.tsv
    continue
  fi
  echo ${vuls} | jq -r '.[] | select(.title? | length > 0) | [.title, .fixed_in] | @tsv' |
    while IFS=$'\t' read -r title fixedin; do
      vul=$(echo ${vuls} | jq -c --arg title "${title}" '.[] | select(.title == $title)')
      if [[ ${fixedin} == "null" ]]; then
        fixedin="nodata"
      fi
      cves=$(echo ${vul} | jq 'select(.references? | length > 0) | .references | select(.cve? | length > 0) | .cve')
      if [[ $(echo ${cves} | jq '. | length') == "" ]]; then
        echo -e "${slug}\t${latest}\t${fixedin}\t${title}\tnodata" >>${OUTDIR}/plugin_vuls.tsv
        continue
      fi
      echo ${cves} | jq -r '.[]' |
        while read cve; do
          echo -e "${slug}\t${latest}\t${fixedin}\t${title}\t${cve}" >>${OUTDIR}/plugin_vuls.tsv
        done
    done
done

##############################
# cve.tsv
##############################
if [[ -f cve_api.result ]]; then
  rm -f ${OUTDIR}/cve_api.result
fi
cat ${OUTDIR}/plugin_vuls.tsv | awk -F"\t" '{ print $5 }' | sed -e '1d' -e '/nodata/d' -e '/^$/d' | sort | uniq |
  while read cve; do
    echo $(curl -s ${CVE_URL}/CVE-${cve}) | sed 's/\\\u\(....\)/\&#x\1;/g' |
      nkf --numchar-input -w | jq -cr --arg cve "${cve}" '{($cve): .}' >>${OUTDIR}/cve_api.result
  done
echo -e "cve_id\tscore" >${OUTDIR}/cve.tsv
cat ${OUTDIR}/cve_api.result | while read -r line; do
  cve=$(echo ${line} | jq -rs '.[] | keys[]')
  items=$(echo ${line} | jq .\"${cve}\" | jq -r '.result.CVE_Items')
  if [[ ${items} == "null" ]]; then
    continue
  fi
  score=$(echo ${line} | jq .\"$cve\" | jq -r '.result.CVE_Items[].impact.baseMetricV3.cvssV3.baseScore')
  if [[ ${score} == "null" ]]; then
    score=$(echo ${line} | jq .\"$cve\" | jq -r '.result.CVE_Items[].impact.baseMetricV2.cvssV2.baseScore')
  fi
  if [[ ${score} == "null" ]]; then
    score="nodata"
  else
    if [[ ${#score} < 2 ]]; then
      score="${score}.0"
    fi
  fi
  echo -e "${cve}\t${score}" >>${OUTDIR}/cve.tsv
done

exit 0
