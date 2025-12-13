# components/radiolib/CMakeLists.txt

# 1. Find all Source Files
file(GLOB_RECURSE SOURCES "src/*.cpp" "src/*.c")

# 2. Find all Header Directories (Recursive)
#    This ensures "SX1278.h" is found even though it is deep in a subfolder.
file(GLOB_RECURSE ALL_HEADERS "src/*.h")
set(INC_DIRS "src")

foreach(HEADER_FILE ${ALL_HEADERS})
    get_filename_component(HEADER_DIR "${HEADER_FILE}" DIRECTORY)
    list(APPEND INC_DIRS "${HEADER_DIR}")
endforeach()

list(REMOVE_DUPLICATES INC_DIRS)

# 3. Register
idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS ${INC_DIRS}
    REQUIRES driver esp_timer
)