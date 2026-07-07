import copy
import logging
import os
import pickle
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Any, Final, Optional

import networkx as nx

ENCODING: Final[str] = "utf-8"

# Tags whose text may contain characters that break XML parsing (unescaped
# & / < / > inside OS_Regex patterns). Their content is captured and replaced
# with placeholders before parsing, then restored afterwards, so conditions
# survive intact instead of being stripped.
UNSAFE_FINDER: re.Pattern[str] = re.compile(
    r'<(regex|match|prematch)(\s[^>]*)?>(.*?)</\1>',
    flags=re.DOTALL | re.IGNORECASE)

REGEX_AMP: re.Pattern[str] = re.compile(r"&(?!amp;|lt;|gt;|quot;|apos;|#)")

PLACEHOLDER_TPL: Final[str] = "__RULEVIS_TXT_{}__"
PLACEHOLDER_RE: re.Pattern[str] = re.compile(r"__RULEVIS_TXT_(\d+)__")

# Wazuh rule child elements that act as matching conditions. Iteration order
# of an ET.Element preserves document order, so conditions keep the order in
# which they were authored in the XML.
CONDITION_TAGS: Final[frozenset[str]] = frozenset({
    "if_sid", "if_group", "if_matched_sid", "if_matched_group", "if_level",
    "if_fts", "match", "regex", "decoded_as", "category", "field", "srcip",
    "dstip", "srcport", "dstport", "user", "srcuser", "dstuser",
    "program_name", "hostname", "id", "url", "location", "action", "status",
    "protocol", "system_name", "data", "extra_data", "srcgeoip", "dstgeoip",
    "weekday", "time", "list",
})

# Rule element attributes worth keeping as node metadata.
RULE_ATTRS: Final[tuple[str, ...]] = (
    "level", "frequency", "timeframe", "ignore", "maxsize", "noalert", "overwrite",
)


class GraphGenerator:
    def __init__(self, paths: list[str], graph_file: str,
                 product_map: Optional[dict[str, str]] = None,
                 source: Optional[str] = None) -> None:
        """
        Args:
            paths: directories to walk for rule XML files.
            graph_file: output pickle path.
            product_map: lowercase file basename -> product name mapping used
                to tag each rule with the product it belongs to.
            source: optional origin label (e.g. a manager name) stored on
                every node, useful for multi-manager/batch analysis.
        """
        self.paths = paths
        self.group_membership: dict[str, list[str]] = defaultdict(list)
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()
        self.graph_file: str = graph_file
        self.overwrite_rules: list[tuple[ET.Element, str]] = []
        self.duplicate_ids: list[dict[str, str]] = []
        self.product_map: dict[str, str] = {
            k.lower(): v for k, v in (product_map or {}).items()}
        self.source: Optional[str] = source

    def get_all_xml_files(self) -> list[str]:
        xml_files: list[str] = []
        for path in self.paths:
            for root, _, files in os.walk(path):
                for file in files:
                    if file.lower().endswith('.xml'):
                        abs = os.path.abspath(os.path.join(root, file))
                        xml_files.append(abs)

        logging.info(f'Found {len(xml_files)} XML files in the given paths')
        logging.info('Processing all files...')
        return xml_files

    def add_edge_with_type(self, source: str, target: str, relation_type: str) -> None:
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            logging.debug(
                f"Adding edge from {source} to {target} with type {relation_type}")
        self.G.add_edge(source, target, relation_type=relation_type)

    def add_relationship_edges(self, rule_id: str,
                               if_sid: Optional[str], if_matched_sid: Optional[str],
                               if_group: Optional[str], if_matched_group: Optional[str]) -> None:
        if if_sid:
            for sid in re.split(r'[,\s]+', if_sid.strip()):
                self.add_edge_with_type(sid.strip(), rule_id, 'if_sid')

        if if_matched_sid:
            for sid in re.split(r'[,\s]+', if_matched_sid.strip()):
                self.add_edge_with_type(sid.strip(), rule_id, 'if_matched_sid')

        if if_group:
            for group in re.split(r'[,\s]+', if_group.strip()):
                for parent_rule in self.group_membership.get(group.strip(), []):
                    self.add_edge_with_type(parent_rule, rule_id, 'if_group')

        if if_matched_group:
            for group in re.split(r'[,\s]+', if_matched_group.strip()):
                for parent_rule in self.group_membership.get(group.strip(), []):
                    self.add_edge_with_type(
                        parent_rule, rule_id, 'if_matched_group')

    def extract_conditions(self, element: ET.Element) -> list[dict[str, Any]]:
        """Ordered list of matching conditions exactly as authored in the XML."""
        conditions: list[dict[str, Any]] = []
        for child in element:
            tag = child.tag.lower()
            if tag in CONDITION_TAGS:
                conditions.append({
                    "tag": tag,
                    "text": (child.text or "").strip(),
                    "attributes": dict(child.attrib),
                })
        return conditions

    def extract_mitre(self, element: ET.Element) -> list[str]:
        ids: list[str] = []
        for mitre in element.findall("mitre"):
            for id_el in mitre.findall("id"):
                if id_el.text:
                    ids.append(id_el.text.strip())
        return ids

    def rule_raw_xml(self, element: ET.Element) -> str:
        clone = copy.deepcopy(element)
        try:
            ET.indent(clone, space="  ")
        except Exception:
            ...
        return ET.tostring(clone, encoding="unicode").strip()

    def parse_groups_and_rules(self, element: ET.Element, inherited_groups: list[str], xml_file: str) -> None:
        if element.tag == 'rule':
            if element.get("overwrite", "").lower() == "yes":
                # defer to second pass
                self.overwrite_rules.append((element, xml_file))
                return

            rule_id = element.get('id', '0')
            rule_level = element.get('level')
            if_sid = element.findtext('if_sid', None)
            if_matched_sid = element.findtext('if_matched_sid', None)
            if_group = element.findtext('if_group', None)
            if_matched_group = element.findtext('if_matched_group', None)

            attributes = [(i.tag, i.text) for i in element]
            rule_description = self.extract_rule_description(attributes)
            all_groups = self.extract_rule_groups(inherited_groups, attributes)

            existing = self.G.nodes.get(rule_id)
            # A node can already exist as an empty placeholder that networkx
            # auto-created when an EARLIER-processed rule's if_sid/if_group
            # forward-referenced this ID before its own <rule> element was
            # parsed (file processing order isn't dependency order). That is
            # NOT a duplicate — it's this rule's first and only definition,
            # and must still be filled in. Only treat it as a real duplicate
            # once a rule with this ID has actually been fully defined
            # (marked by the presence of "conditions").
            if existing is not None and "conditions" in existing:
                logging.debug(
                    f"Duplicate rule ID found with no 'overwrite' tag: {rule_id}. User must fix the rule manually.")
                self.duplicate_ids.append({
                    "id": rule_id, "file": os.path.basename(xml_file),
                    "existing_file": existing.get("file", ""),
                })

            else:
                basename = os.path.basename(xml_file)
                node_attrs: dict[str, Any] = {
                    "groups": all_groups,
                    "description": rule_description,
                    "level": rule_level,
                    "file": basename,
                    "path": xml_file,
                    "product": self.product_map.get(basename.lower()),
                    "conditions": self.extract_conditions(element),
                    "mitre": self.extract_mitre(element),
                    "raw": self.rule_raw_xml(element),
                }
                for attr in RULE_ATTRS:
                    val = element.get(attr)
                    if val is not None:
                        node_attrs[attr] = val
                if self.source:
                    node_attrs["source"] = self.source

                self.G.add_node(rule_id, **node_attrs)
                for group in all_groups:
                    self.group_membership[group].append(rule_id)

                self.add_relationship_edges(
                    rule_id, if_sid, if_matched_sid, if_group, if_matched_group)

        elif element.tag == 'group':
            group_attribute = element.get('name', '')
            internal_groups = [
                gr for gr in group_attribute.split(',') if gr != '']
            new_inherited_groups = inherited_groups + internal_groups

            for child in element:
                self.parse_groups_and_rules(child, new_inherited_groups, xml_file)

    def extract_rule_groups(self, inherited_groups: list[str], children: list[tuple[str, Optional[str]]]) -> list[str]:
        all_groups = list(inherited_groups)
        for child in children:
            if child[0] == 'group' and child[1]:
                all_groups.extend([g for g in child[1].split(',') if g])
        return all_groups

    def extract_rule_description(self, attributes: list[tuple[str, Optional[str]]]) -> Optional[str]:
        description: list[str] = []
        for attr in attributes:
            if attr[0] == 'description':
                d = attr[1]
                if d:
                    description.append(d)
        if len(description) > 0:
            return ' '.join(description)
        return None

    def wrap_with_root(self, xml_content: str) -> str:
        return f"<root>{xml_content}</root>"

    def build_graph_from_xml(self) -> None:
        xml_files = self.get_all_xml_files()

        for xml_file in xml_files:
            logging.info(f'Processing file: {xml_file}')
            try:
                with open(xml_file, 'r', encoding=ENCODING, errors="replace") as f:
                    xml_content = f.read()
            except OSError as e:
                logging.error(
                    f"Error reading file {xml_file}: {e}", exc_info=True)
                continue

            wrapped_content: str = self.wrap_with_root(xml_content)

            try:
                sanitized, captured = self.__capture_unsafe_text(wrapped_content)
                sanitized = self.__escape_amp(sanitized)
                parsed_xml = ET.fromstring(sanitized)
                self.__restore_placeholders(parsed_xml, captured)
                root = parsed_xml
                for child in root:
                    self.parse_groups_and_rules(child, [], xml_file)
            except Exception as e:
                logging.error(f"Error parsing {xml_file}: {e}", exc_info=True)

        # second pass: apply overwrites now that all base rules exist
        # Per Wazuh documentation, the overwrite tag is "used to replace a rule
        # with local changes. To maintain consistency between loaded rules,
        # if_sid, if_group, if_level, if_matched_sid, and if_matched_group
        # labels are not taken into account when overwriting a rule. If any of
        # these are encountered, the original value prevails."
        # Therefore, we intentionally do NOT update groups or dependency
        # relationships (if_sid, if_group, etc.) when applying overwrites.
        for element, ow_file in self.overwrite_rules:
            # Only description, level, maxsize, and file are updated
            rule_id = element.get("id")
            if rule_id in self.G.nodes:
                existing = self.G.nodes[rule_id]
                logging.info(f"Applying overwrite for rule {rule_id}")
                attrs = [(i.tag, i.text) for i in element]
                desc = self.extract_rule_description(attrs)
                if desc:
                    existing["description"] = desc
                for attr in ("level", "maxsize"):
                    if element.get(attr):
                        existing[attr] = element.get(attr)
                basename = os.path.basename(ow_file)
                existing["file"] = basename
                existing["path"] = ow_file
                existing["overwritten"] = True
                existing["raw_overwrite"] = self.rule_raw_xml(element)
                if self.product_map.get(basename.lower()):
                    existing["product"] = self.product_map.get(basename.lower())
            else:
                logging.warning(
                    f"Overwrite rule {rule_id} found with no base rule; skipping.")

        first_level_rules = [
            node for node in self.G.nodes if self.G.in_degree(node) == 0]

        # Add synthetic root and connect to top-level rules
        synthetic_root = '0'  # Root has ID of 0
        self.G.add_node(
            synthetic_root, description="Synthetic root node", groups=["__meta__"])

        for node in first_level_rules:
            self.add_edge_with_type(synthetic_root, node, "root")

        # Pre-calculate and store all children for every node.
        # This is crucial for the frontend to know if a node is fully expanded.
        logging.info("Pre-calculating child relationships...")
        for node_id in list(self.G.nodes):
            # G.successors(node_id) returns an iterator of all direct children
            children_ids = list(self.G.successors(node_id))
            # Store this list as a new attribute on the node itself.
            self.G.nodes[node_id]['children_ids'] = children_ids
        logging.info("Child relationship calculation complete.")

        logging.info(f"Total nodes: {self.G.number_of_nodes()}")
        logging.info(
            f"First-level children (connected to root): {len(list(self.G.successors('0')))}")

        self.G.graph["duplicate_rule_ids"] = self.duplicate_ids

    def save_graph(self) -> None:
        try:
            output_path = self.graph_file
            dirname = os.path.dirname(output_path)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            pickle.dump(self.G, open(output_path, 'wb'))
            logging.info(f"Graph saved to {output_path}")
        except Exception as e:
            logging.error(f"Error saving graph: {e}", exc_info=True)

    def __capture_unsafe_text(self, xml_string: str) -> tuple[str, list[str]]:
        """
        Replaces the content of tags that commonly hold regex patterns
        (<regex>, <match>, <prematch>) with numbered placeholders so the
        document parses even when patterns contain raw &, < or >. The captured
        content is restored onto the parsed tree afterwards, preserving the
        full rule definition instead of discarding it.
        """
        captured: list[str] = []

        def _repl(m: re.Match) -> str:
            idx = len(captured)
            captured.append(m.group(3))
            attrs = m.group(2) or ""
            return f"<{m.group(1)}{attrs}>{PLACEHOLDER_TPL.format(idx)}</{m.group(1)}>"

        return UNSAFE_FINDER.sub(_repl, xml_string), captured

    def __restore_placeholders(self, root: ET.Element, captured: list[str]) -> None:
        if not captured:
            return
        for el in root.iter():
            if el.text and "__RULEVIS_TXT_" in el.text:
                el.text = PLACEHOLDER_RE.sub(
                    lambda m: captured[int(m.group(1))], el.text)

    def __escape_amp(self, xml_string: str) -> str:
        sanitized_string = REGEX_AMP.sub("&amp;", xml_string)
        return sanitized_string
