# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

class EntityTy(object):
    T_INVALID = 0
    T_TFC = 1
    T_TFC_LOOP = 2
    T_TFC_CRASH = 3
    T_TFC_TMC_REPORT = 4
    T_ROAD_SEGMENT = 5
    T_INTERSECTION = 6
    T_SIDEWAlK = 7
    T_BIKEWAY = 8
    T_TRANSIT_LINE = 9
    T_BIA = 10
    T_NEIGHBOURHOOD = 11
    T_NIA = 12
    T_WARD = 13
    T_DISTRICT = 14
    T_CONSTITUENCY = 15
    T_POSTAL_CODE_GEO = 16
    T_BUSINESS = 17
    T_LAND_PARCEL = 18
    T_ADDRESS = 19
    T_POSTAL_CODE_DEMOGRAPHICS = 20
    T_ZONE = 21
    T_PARK = 22
    T_PARKING_LOT = 23
    T_PARKING_TICKET = 24
    T_PLACE_OF_INTEREST = 25
    T_DAYCARE_CENTRE = 26
    T_MEDICAL_CENTRE = 27
    T_COMMERCIAL_LAND = 28
    T_DEVELOPMENT_APPLICATION = 29
    T_AVAILABLE_COMMERCIAL_SPACE = 30
    T_BUILDING_FOOTPRINT = 31
    T_DEVELOPED_EMPLOYMENT_LAND = 32
    T_VACANT_EMPLOYMENT_LAND = 33
    T_STREET = 34
    T_BIKESHARE_STATION = 35
    T_SUBWAY_LINE = 36
    T_ON_STREET_PARKING = 37
    T_PEDESTRIAN_ROUTE = 38
    T_HERITAGE_DISTRICT = 39
    T_BUS_ROUTE = 40
    T_BUS_STOP = 41
    T_POLITICAL_BOUNDARY = 42
    T_CRIME = 43
    T_EVENT = 44
    T_TFC_SEGMENT_VOLUMES = 45
    T_TFC_TMC_COUNTS = 46
    T_TFC_AADT = 47
    T_CONNECTIVITY_CORRIDORS = 48
    T_MEDIANS = 49
    T_EVACUATION_ROUTES = 50
    T_TRAFFIC_METRICS = 51
    T_COUNTERMEASURES_DEVICES = 52
    T_TRAFFIC_INCIDENTS = 53
    T_BLOCKGROUP_DEMOGRAPHIC = 54
    T_PARKING_METER = 55
    T_PROPERTY_VALUE_ASSESSMENT = 56
    T_GOLF_COURSE = 57
    T_BUILDING_PERMIT = 58
    T_REALM = 59
    T_ROAD_SEGMENT_COUNT_LOCATION = 60
    T_INTERSECTION_COUNT_LOCATION = 61
    T_TRIPS_ORIGIN_DESTINATION_PASSTHROUGH_BIA = 62
    T_WORKLOGS = 63
    T_FORECAST = 64
    T_BRIDGES = 65
    T_OPEN_MARKETS = 66
    T_BIKE_FACILITIES = 67
    T_DOG_LICENCES = 68
    T_PEDESTRIAN_COUNT_LOCATION = 69
    T_DISADVANTAGED_AREA = 70
    T_TRANSPORTATION_ANALYSIS_ZONE = 71
    T_ELECTION_DISTRICT = 72
    T_DISSEMINATION_AREA = 73
    T_RETAIL_AREA = 74
    T_GROWTH_CENTER = 75
    T_SEARCH_ATTRIBUTES = 76
    T_PROPERTY = 77
    T_DESIGNATED_AREA = 78
    T_PROVINCIAL_FOREST = 79
    T_TIMBER_SUPPLY_AREA = 80
    T_COMMUNICATION_SITE = 81
    T_CUT_BLOCK = 82
    T_PERMIT = 83
    T_LICENCE = 84
    T_MAP_NOTATION = 85
    T_REAL_PROPERTY_PROJECT = 86
    T_RECREATION_SITE = 87
    T_RECREATION_LINE = 88
    T_RECREATION_POLYGON = 89
    T_SPECIAL_ACCESS_ROAD = 90
    T_GROWTH_YIELD_SAMPLE = 91
    T_OLD_GROWTH_MANAGEMENT_AREA = 92
    T_TREATY_AREA = 93
    T_TREATY_LAND = 94
    T_RELATED_TREATY_LAND = 95
    T_ALC_ALR = 96
    T_CONSERVATION_LAND = 97
    T_MINFILE_MINERAL_OCCURRENCE_DATABASE = 98
    T_CROWN_GRANTED_MINERAL_CLAIM = 99
    T_MINERAL_RESERVES_SITES_BUSINESS_VIEW = 100
    T_PETROLEUM_TITLE = 101
    T_CONSERVANCY_AREA = 102
    T_WILDLIFE_MANAGEMENT_AREA = 103
    T_RESERVOIR_PERMIT = 104
    T_WATER_LICENSED_WORK = 105
    T_WATER_RIGHTS_APPLICATION = 106
    T_WATER_RIGHTS_LICENCE = 107
    T_GUIDE_OUTFITTER_AREA = 108
    T_UNGULATE_WINTER_RANGE = 109
    T_WILDLIFE_HABITAT_AREAS = 110
    T_ROAD_SEGMENT_EXACT_COUNT_LOCATION = 111
    T_EASEMENT = 112
    T_STREET_LIGHT = 113
    T_TRAIL = 114
    T_ROAD_SEGMENT_TRAVEL_TIME_LOCATION = 115
    T_CONSTRUCTION_PROJECT = 116
    T_FACILITY = 117
    T_SUBDIVISION_APPLICATION = 118
    T_GARBAGE_ROUTE = 119
    T_PUBLIC_ART = 120
    T_CENSUS_TRACTS_DEMOGRAPHIC = 121
    T_COMMUNITY_OF_CONCERN = 122
    T_LIBRARY = 123
    T_SCHOOL = 124
    T_STREET_TREE = 125
    T_ELECTRIC_VEHICLE_CHARGING_STATION = 126
    T_VISION_ZERO_SAFETY_CORRIDOR = 127
    T_TRAFFIC_VOLUME_MODEL = 128
    T_PLANNING_PROJECT = 129
    T_PHARMACY = 130
    T_CENSUS_BLOCK = 131
    T_ZIP_CODE = 132
    T_FIRE_ASSESSMENT = 133
    T_TRANSPORTATION_PAVEMENT = 134
    T_VEHICLE = 135
    T_TRIBAL_LAND = 136
    T_FIRE_STATION = 137
    T_WILDFIRE = 138
    T_ACTIVE_TRANSPORTATION_LOCATION = 139
    T_TIME_DENSITY = 140
    T_YOUTH_DISABILITY_SUPPORT_SERVICES = 141
    T_HOME_FIRE_RISK = 142
    T_COUNT_LOCATION = 143
    T_RAILROAD = 144
    T_COMMUNITY_CENTER = 145
    T_MEAL_SITE = 146
    T_FOOD_BANK_AND_PARTNER = 147
    T_HOUSING_UNIT = 148
    T_BIKE_RACK = 149
    T_IMPROVEMENT_AREA = 150
    T_ZONING_DISTRICT = 151
    T_RIGHT_OF_WAY = 152
    T_FREEWAY = 153
    T_BIKE_SUPPORT = 154
    T_BIKE_CROSSING = 155
    T_CYCLING_JUNCTION = 156
    T_LANEWAYS = 157
    T_CROSSWALK = 158
    T_ISSUE = 159
    T_MONUMENT = 160
    T_WATER_PARCEL = 161
    T_CONTOUR = 162
    T_CAPITAL_PROJECT = 163
    T_SIGN = 164
    T_SIGN_POLE = 165
    T_REQUEST = 166
    T_EMERGENCY_RESPONSE_ROAD = 167
    T_RAILWAY_CROSSING = 168
    T_MOBILITY_HUB = 169
    T_CORRIDOR = 170
    T_CRASH = 171
    T_RAIL_LINE = 172
    T_RAIL_STOP = 173
    T_ROUTE = 174
    T_ROUTE_STOP = 175
    T_TRANSIT_STOP = 176
    T_TRANSIT_CENTER = 177
    T_EXPLORE_MODE_INTERSECTION = 178
    T_ETS_SEGMENT = 179
    T_FSA = 180
    T_NEIGHBORHOOD_BUSINESS_ASSOCIATION = 181
    T_COUNCIL_DISTRICT = 182
    T_PROJECT_CRASHBOARD = 183
    T_ELEVATION_LINE = 184
    T_AREA = 185
    T_TAX_LOT = 186
    T_FLOOD = 187
    T_COUNTY = 188
    T_CITY = 189
    T_ELEMENTARY_SCHOOL_DISTRICT = 190
    T_HIGH_SCHOOL_DISTRICT = 191
    T_MIDDLE_SCHOOL_DISTRICT = 192
    T_POLICY_AREA = 193
    T_2020_CENSUS_BLOCK = 194
    T_2010_CENSUS_BLOCK = 195
    T_2020_CENSUS_TRACT = 196
    T_NON_CTP_ROADS = 197
    T_COMMERCIAL_VACANCY = 198
    T_TESTING_SITE = 199
    T_CLINIC = 200
    T_STREET_LITTER = 201
    T_CHILDCARE_CENTER = 202
    T_CAMERA = 203
    T_ALLEY = 204
    T_PAVEMENT = 205
    T_PAVEMENT_STRIP = 206
    T_POLE = 207
    T_DASHBOARD_BUSINESS = 208
    T_SIGNAL = 209
    T_MAST_ARM = 210
    T_CAMERA_EXPLORE = 211
    T_DASHBOARD_PROPERTY = 212
    T_POLICE_REPORTED_CRASH = 213
    T_PARKING_SPACE = 214
    T_FIRE_RISK_SCORE = 215
    T_FIRE_RISK_CAUSE = 216
    T_FIRE_DEPARTMENT = 217
    T_PLANNED_SIDEWALK = 218
    T_PROPOSED_PEDESTRIAN_PROJECT = 219
    T_PROPOSED_BIKE_PROJECT = 220
    T_ADMINISTRATIVE_AREA = 221
    T_CURB_RAMP = 222
    T_PARKING_PERMIT_AREA = 223
    T_PARCEL = 224
    T_BOUNDARY = 225
    T_RAILWAY = 226
    T_SOIL = 227
    T_UTILITY_CABINET = 228
    T_SIGNAL_CABINET = 229
    T_PEDESTRIAN_BUTTON = 230
    T_TRAFFIC_CALMING = 231
    T_CURB = 232
    T_TRUCK_ROUTE = 233
    T_GREENWAY = 234
    T_ROAD_EDGE = 235
    T_RESTAURANT = 236
    T_BARRIER = 237
    T_PAVEMENT_MARKING = 238
    T_PLANNING_AREA = 239
    T_ORDER = 240
    T_FIRE_HYDRANT = 241
    T_CANNABIS_AND_LIQUOR_STORES = 242
    T_CENSUS_SUBDIVISION = 243
    T_SPEED_HUMP = 244
    T_CRASH_CUSHION = 245
    T_DEFAULT_AREA_FILTER = 246
    T_PLAYGROUND = 247
    T_PICNIC_SHELTER = 248
    T_TENNIS_COURT = 249
    T_SPORTS_FIELD = 250
    T_WASHROOM = 251
    T_BASEBALL_DIAMOND = 252
    T_ITS_DEVICE = 253
    T_SHORTLINE = 254
    T_TRANSIT_RELATED = 255
    T_FREIGHT_ANALYSIS_DASHBOARD = 256
    T_ACCESS_POINT = 257
    T_CENSUS_DIVISION = 258
    T_STATE_PROVINCE = 259
    T_FEDERAL = 260
    T_CANNABIS_AND_LIQUOR_STORES_TRANSFER = 261