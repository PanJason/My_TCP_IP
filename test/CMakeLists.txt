file(GLOB tests_src "*.cpp")

foreach(test_src IN LISTS tests_src)
    get_filename_component(test_name ${test_src} NAME_WE)
    add_executable(${test_name} ${test_src})
    target_link_libraries(${test_name} PUBLIC link)
endforeach(test_src IN LISTS tests_src)