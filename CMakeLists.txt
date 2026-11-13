cmake_minimum_required(VERSION 3.24)
project(culprit LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# Static CRT: one exe, no redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CULPRIT_VERSION "0.0.0-dev" CACHE STRING "Version string baked into the binary")

# --- Core: everything except main(), so tests can link it -------------------
add_library(culprit_core STATIC
  src/score.cpp
  src/proctree.cpp
  src/recorder.cpp
  src/format.cpp
  src/history.cpp
  src/sampler.cpp
  src/inspect.cpp
  src/kill.cpp
  src/track.cpp
  src/engine.cpp
  src/ui.cpp)
target_include_directories(culprit_core PUBLIC src)
target_compile_definitions(culprit_core PUBLIC
  UNICODE _UNICODE NOMINMAX
  CULPRIT_VERSION="${CULPRIT_VERSION}")
target_link_libraries(culprit_core PUBLIC
  version wintrust crypt32 advapi32 shell32 ole32 oleaut32 taskschd)
if(MSVC)
  target_compile_options(culprit_core PUBLIC /W4 /utf-8 /permissive-)
endif()

add_executable(culprit src/main.cpp)
target_link_libraries(culprit PRIVATE culprit_core)

enable_testing()
add_executable(culprit_tests tests/tests.cpp)
target_link_libraries(culprit_tests PRIVATE culprit_core)
add_test(NAME culprit_tests COMMAND culprit_tests)
