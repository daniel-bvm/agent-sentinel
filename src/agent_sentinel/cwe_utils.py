from dataclasses import dataclass, field
from typing import List, Optional
from lxml import etree
import os, requests

import logging

logger = logging.getLogger(__name__)

@dataclass
class CWEWeakness:
    id: str
    name: str
    description: Optional[str]
    extended_description: Optional[str]
    abstraction: Optional[str]
    status: Optional[str]
    likelihood: Optional[str]
    consequences: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    cve_refs: List[str] = field(default_factory=list)

def parse_cwe_weaknesses(xml_path: str) -> List[CWEWeakness]:
    ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}
    tree = etree.parse(xml_path)
    root = tree.getroot()
    
    weaknesses = []
    for elem in root.xpath('//cwe:Weakness', namespaces=ns):
        id_ = elem.attrib.get("ID")
        name = elem.attrib.get("Name")
        abstraction = elem.attrib.get("Abstraction")
        status = elem.attrib.get("Status")

        desc_elem = elem.find('cwe:Description', namespaces=ns)
        ext_desc_elem = elem.find('cwe:Extended_Description', namespaces=ns)
        description = desc_elem.text.strip() if desc_elem is not None else None
        extended_description = (
            ''.join(ext_desc_elem.itertext()).strip() if ext_desc_elem is not None else None
        )

        # Consequences
        consequences = []
        for cons_elem in elem.xpath('.//cwe:Common_Consequences/cwe:Consequence', namespaces=ns):
            for impact in cons_elem.xpath('.//cwe:Impact', namespaces=ns):
                consequences.append(impact.text)

        # CVE References
        cve_refs = []
        for ref in elem.xpath('.//cwe:Observed_Examples/cwe:Observed_Example/cwe:Reference', namespaces=ns):
            cve_refs.append(ref.text)

        # Example Code Snippets
        examples = []
        for code in elem.xpath('.//cwe:Demonstrative_Examples/cwe:Demonstrative_Example/cwe:Example_Code', namespaces=ns):
            examples.append(''.join(code.itertext()).strip())

        # Likelihood of exploit
        likelihood_elem = elem.find('cwe:Likelihood_Of_Exploit', namespaces=ns)
        likelihood = likelihood_elem.text.strip() if likelihood_elem is not None else None

        weaknesses.append(
            CWEWeakness(
                id=id_,
                name=name,
                description=description,
                extended_description=extended_description,
                abstraction=abstraction,
                status=status,
                likelihood=likelihood,
                consequences=consequences,
                examples=examples,
                cve_refs=cve_refs
            )
        )

    return weaknesses

DEFINITION_LINK_FMT = "https://cwe.mitre.org/data/definitions/{cwe_id}.html"
DB_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
DB_LOCAL_PATH = "./storage/cwec_latest.xml.zip"

os.makedirs("./storage", exist_ok=True)

from functools import lru_cache
import zipfile
import time 
import tempfile
import glob
import re

def validate_local_db(path: str) -> bool:
    last_updated = os.path.getmtime(path)
    
    if last_updated < time.time() - 86400:
        return False

    return True

def download_db() -> str | None:
    global DB_URL, DB_LOCAL_PATH
    

    tmp_file = f"{DB_LOCAL_PATH}.tmp"
    try:
        resp = requests.get(DB_URL)

        assert resp.status_code == 200, f"Failed to download CWE database: {resp.status_code}"

        with open(tmp_file, 'wb') as f:
            f.write(resp.content)

        return tmp_file
    except Exception as err:
        return None

@lru_cache(maxsize=1)
def get_db() -> List[CWEWeakness]:
    global DB_URL

    if not os.path.exists(DB_LOCAL_PATH) or not validate_local_db(DB_LOCAL_PATH):
        newly_file = download_db()

        if newly_file is not None and os.path.exists(newly_file):
            os.rename(newly_file, DB_LOCAL_PATH)

    if not os.path.exists(DB_LOCAL_PATH):
        logger.error(f"CWE database not found: {DB_LOCAL_PATH}")
        return []

    with zipfile.ZipFile(DB_LOCAL_PATH, 'r') as zip_ref, tempfile.TemporaryDirectory() as tmp_dir:
        os.makedirs(tmp_dir, exist_ok=True)

        try:
            zip_ref.extractall(tmp_dir)
        except Exception as err:
            logger.error(f"Failed to extract CWE database: {err}")
            return []
    
        xml_files = glob.glob(os.path.join(tmp_dir, '*.xml')) 
        
        if len(xml_files) == 0:
            logger.error(f"No XML files found in the CWE database: {tmp_dir}")
            return []
        
        if len(xml_files) > 1:
            logger.warning(f"Multiple XML files found in the CWE database: {xml_files}")

        xml_file = xml_files[0]
        return parse_cwe_weaknesses(xml_file)

def get_cwe_by_id(cwe_id: str | int) -> CWEWeakness | None:
    if isinstance(cwe_id, str):
        pat = re.compile(r"CWE-\d+", re.IGNORECASE)
        cwe_ids = pat.findall(cwe_id)

        if len(cwe_ids) == 0:
            return None
        
        if len(cwe_ids) > 1:
            logger.warning(f"Multiple CWE IDs found in the CWE ID: {cwe_id}")

        cwe_id = cwe_ids[0]
        cwe_id = str(cwe_id)

    else:
        cwe_id = str(cwe_id)

    for weakness in get_db():
        if weakness.id == cwe_id:
            return weakness

    return None
