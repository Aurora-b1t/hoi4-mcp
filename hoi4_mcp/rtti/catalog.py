"""Curated class catalog for key game objects (v1 scope).

Offsets for struct fields live in tables/generated/offsets.json; this file
only pairs a stable tooling name with the RTTI class name so readers can
resolve objects via vftables at runtime.
"""

KEY_CLASSES = {
    "game_state":       [r"^\.\?AVCGameState@@"],
    "country":          [r"^\.\?AVCCountry@@"],
    "province":         [r"^\.\?AVC Province@@$"],
    "army":             [r"^\.\?AVCArmy@$"],
    "army_group":       [r"^\.\?AVCArmyGroup@$"],
    "front":            [r"^\.\?AVCFront@@"],
    "front_section":    [r"^\.\?AVCFrontSection@@"],
    "focus_tree":       [r"^\.\?AVCNationalFocusTree@@"],
    "focus":            [r"^\.\?AVCNationalFocus@@"],
    "focus_progress":   [r"^\.\?AVCNationalFocusProgress@@"],
    "decision":         [r"^\.\?AVCDecision@@"],
    "decision_status":  [r"^\.\?AVCDecisionStatus@@"],
    "technology":       [r"^\.\?AVCTechnology@@$"],
    "technology_status":[r"^\.\?AVCTechnologyStatus@@"],
    "idea":             [r"^\.\?AVCIdea@@$"],
    "production_line":  [r"^\.\?AVCProductionLine@@$"],
    "building":         [r"^\.\?AVCBuilding@@$"],
    "state":            [r"^\.\?AVCState@@$"],
    "war":              [r"^\.\?AVCWar@@$"],
    "faction":          [r"^\.\?AVCFaction@@$"],
    "player":           [r"^\.\?AVCPlayer@@$"],
    "game_rules":       [r"^\.\?AVCGameRulesInstance@@"],
    "unit_leader":      [r"^\.\?AVCArmyLeader@?$", r"^\.\?AVCArmyLeader@@$"],
    "division_template":[r"^\.\?AVCDivisionTemplate@?$", r"^\.\?AVCCountryTemplate@?$"],
    "equipment":        [r"^\.\?AVCEquipment(?:Version|Type)?@?$"],
}
