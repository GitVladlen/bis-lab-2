# Properties->C/C++->General->Additional Include Directories
##include_directories ("${PROJECT_SOURCE_DIR}/Math")
 
# Set Properties->General->Configuration Type to Application(.exe)
# Creates app.exe with the listed sources (main.cxx)
# Adds sources to the Solution Explorer
set(MY_PROJECT_SOURCES
    main.cpp
)

add_executable(${MY_PROJECT_NAME} ${MY_PROJECT_SOURCES})
 
# Properties->Linker->Input->Additional Dependencies
##target_link_libraries (app math)
 
# Creates a folder "executables" and adds target 
# project (app.vcproj) under it
set_property(TARGET ${MY_PROJECT_NAME} PROPERTY FOLDER "executables")
 
# Properties->General->Output Directory
set_target_properties(${MY_PROJECT_NAME} PROPERTIES
                      RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
 
# Adds logic to INSTALL.vcproj to copy app.exe to destination directory
install (TARGETS ${MY_PROJECT_NAME}
         RUNTIME DESTINATION ${PROJECT_SOURCE_DIR}/_install)