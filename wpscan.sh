#!/bin/bash

set -e -o pipefail

. ~/.bash_profile
CVE_URL="https://services.nvd.nist.gov/rest/json/cve/1.0"
WPSCAN_URL="https://wpscan.com/api/v3"
DATE=$(date '+%Y%m%d')
DIR_NAME="output"
OUTDIR="/home/ubuntu/wpscan/${DIR_NAME}/${DATE}"
MYCNF="/home/ubuntu/.my.wpscan.cnf"
# OUTDIR="output" # debug

if [[ ${WPSCAN_API_KEY} == "" ]]; then
  echo "Require WPSCAN API KEY!"
  exit 1
fi

mkdir -p ${OUTDIR}

##############################
## mainwp medias.tsv
##############################
echo -e "wpid\tname\turl" >${OUTDIR}/medias.tsv
mysql mainwp-prd --defaults-file=${MYCNF} -B -N -e 'select id, name, url from wp_mainwp_wp' >>${OUTDIR}/medias.tsv

##############################
## mainwp cores.tsv
##############################
echo -e "wpid\twp_version" >${OUTDIR}/cores.tsv
mysql mainwp-prd --defaults-file=${MYCNF} -B -N -e 'select wpid, value from wp_mainwp_wp_options where name="last_wp_upgrades" order by wpid' |
  while IFS=$'\t' read wpid option; do
    version=$(echo ${option} | jq -r 'select(.current? | length > 0) | .current')
    if [[ ${version} == "" ]]; then
      version="nodata"
    fi
    echo -e "${wpid}\t${version}" >>${OUTDIR}/cores.tsv
  done

##############################
## wpscan core_vuls.tsv
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
mysql mainwp-prd --defaults-file=${MYCNF} -B -N -r -e 'select id, plugins from wp_mainwp_wp order by id' |
  while IFS=$'\t' read -r wpid plugins_json; do
    echo ${plugins_json} | jq -r '.[] | [(.slug | split("/") | .[0]), .version] | @tsv' |
      while IFS=$'\t' read -r slug version; do
        echo -e "${wpid}\t${slug}\t${version}" >>${OUTDIR}/plugins.tsv
      done
  done

##############################
## wpscan plugin_vuls.tsv
##############################
if [[ -f wpscan_plugins_api.result ]]; then
  rm -f ${OUTDIR}/wpscan_plugins_api.result
fi
cat ${OUTDIR}/plugins.tsv | awk -F"\t" '{ print $2 }' | sed -e '1d' -e '/nodata/d' | sort | uniq >${OUTDIR}/plugin.list
cat ${OUTDIR}/plugin.list | while read slug; do
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
  if [[ ${latest} == "" ]]; then
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
      if [[ ${fixedin} == "" ]]; then
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
## cve.tsv
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
  fi
  echo -e "${cve}\t${score}" >>${OUTDIR}/cve.tsv
done

##############################
## vulnerabilities.tsv
##############################
if [[ -f ${OUTDIR}/vulnerabilities.tsv ]]; then
  rm -f ${OUTDIR}/vulnerabilities.tsv
fi
while IFS=$'\t' read -r wpid name url; do
  while IFS=$'\t' read -r cores_wpid cores_version; do
    if [[ ${cores_wpid} == ${wpid} ]]; then
      core_version=${cores_version}
      break
    fi
  done < <(cat ${OUTDIR}/cores.tsv)
  while IFS=$'\t' read -r core_vuls_version core_vuls_fixedin core_vuls_title; do
    if [[ ${core_vuls_version} == ${core_version} ]]; then
      core_fixedin=${core_vuls_fixedin}
      core_title=${core_vuls_title}
      if [[ ${core_version} == "nodata" || ${core_fixedin} == "nodata" ]]; then
        continue
      fi
      format_core_version=$(echo ${core_version} | sed 's/\.//g')
      format_core_fixedin=$(echo ${core_fixedin} | sed 's/\.//g')
      if [[ ${format_core_version} == ${format_core_fixedin} ]]; then
        continue
      fi
      digits_core_version=${#format_core_version}
      digits_core_fixedin=${#format_core_fixedin}
      splits_core_version=(${core_version//\./ })
      splits_core_fixedin=(${core_fixedin//\./ })
      flag="true"
      if ((digits_core_version == digits_core_fixedin)); then
        digits=$((digits_core_version - 1))
      elif ((digits_core_version < digits_core_fixedin)); then
        digits=$((digits_core_version - 1))
      else
        digits=$((digits_core_fixedin - 1))
      fi
      for i in $(seq 0 ${digits}); do
        if ((splits_core_version[i] == splits_core_fixedin[i])); then
          continue
        fi
        if ((splits_core_version[i] > splits_core_fixedin[i])); then
          flag="false"
          break
        fi
      done
      if [[ ${flag} == "true" ]]; then
        echo -e "${wpid}\t${name}\t${url}\tcore\tnodata\t${core_version}\t${core_fixedin}\t${core_title}\tnodata\tnodata" >>${OUTDIR}/vulnerabilities.tsv
      fi
    fi
  done < <(cat ${OUTDIR}/core_vuls.tsv)
  while IFS=$'\t' read -r plugins_wpid plugins_slug plugins_version; do
    if [[ ${plugins_wpid} == ${wpid} ]]; then
      plugin_slug=${plugins_slug}
      plugin_version=${plugins_version}
      while IFS=$'\t' read -r plugin_vuls_slug plugin_vuls_latest plugin_vuls_fixedin plugin_vuls_title plugin_vuls_cve_id; do
        if [[ ${plugin_vuls_slug} == ${plugin_slug} ]]; then
          plugin_latest=${plugin_vuls_latest}
          plugin_fixedin=${plugin_vuls_fixedin}
          plugin_title=${plugin_vuls_title}
          plugin_cve_id=${plugin_vuls_cve_id}
          if [[ ${plugin_version} == "nodata" || ${plugin_fixedin} == "nodata" ]]; then
            continue
          fi
          set +e
          cve_score=$(cat ${OUTDIR}/cve.tsv | sed '1d' | grep "${plugin_cve_id}" | awk -F"\t" '{ print $2 }')
          set -e
          if [[ ${cve_score} == "" ]]; then
            cve_score="nodata"
          fi
          format_plugin_version=$(echo ${plugin_version} | sed 's/\.//g')
          format_plugin_fixedin=$(echo ${plugin_fixedin} | sed 's/\.//g')
          if [[ ${format_plugin_version} == ${format_plugin_fixedin} ]]; then
            continue
          fi
          digits_plugin_version=${#format_plugin_version}
          digits_plugin_fixedin=${#format_plugin_fixedin}
          splits_plugin_version=(${plugin_version//\./ })
          splits_plugin_fixedin=(${plugin_fixedin//\./ })
          flag="true"
          if ((digits_plugin_version == digits_plugin_fixedin)); then
            digits=$((digits_plugin_version - 1))
          elif ((digits_plugin_version < digits_plugin_fixedin)); then
            digits=$((digits_plugin_version - 1))
          else
            digits=$((digits_plugin_fixedin - 1))
          fi
          for i in $(seq 0 ${digits}); do
            if ((splits_plugin_version[i] == splits_plugin_fixedin[i])); then
              continue
            fi
            if ((splits_plugin_version[i] > splits_plugin_fixedin[i])); then
              flag="false"
              break
            fi
          done
          if [[ ${flag} == "true" ]]; then
            echo -e "${wpid}\t${name}\t${url}\tplugin\t${plugin_slug}\t${plugin_version}\t${plugin_fixedin}\t${plugin_title}\t${plugin_cve_id}\t${cve_score}" >>${OUTDIR}/vulnerabilities.tsv
          fi
          break
        fi
      done < <(cat ${OUTDIR}/plugin_vuls.tsv | sed '1d')
    fi
  done < <(cat ${OUTDIR}/plugins.tsv | sed '1d')
done < <(cat ${OUTDIR}/medias.tsv | sed '1d')

##############################
## S3 Upload
##############################
/usr/local/bin/aws s3 sync --delete --exclude=.keep /home/ubuntu/wpscan/${DIR_NAME}/ ${WPSCAN_S3_BUCKET}

exit 0
