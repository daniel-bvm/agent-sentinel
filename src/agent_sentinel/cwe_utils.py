from dataclasses import dataclass, field
from typing import List, Optional
from lxml import etree

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