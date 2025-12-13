# main/CMakeLists.txt

idf_component_register(
    SRCS "main.cpp"
    INCLUDE_DIRS "."
    # CRITICAL: Use the EXACT folder names located in 'components/'
    REQUIRES nvs_flash driver ascon PQClean radiolib
)



