// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for configuration file parsing.

#include "config.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

// Helper: write a temporary config file and return its path
static std::string write_temp_config(const std::string& content) {
    char tmpname[] = "/tmp/flowcoin_test_config_XXXXXX";
    int fd = mkstemp(tmpname);
    assert(fd >= 0);
    FILE* f = fdopen(fd, "w");
    assert(f != nullptr);
    std::fputs(content.c_str(), f);
    std::fclose(f);
    return std::string(tmpname);
}

// Helper: clean up temp file
static void remove_temp(const std::string& path) {
    std::remove(path.c_str());
}

void test_config() {
    // -----------------------------------------------------------------------
    // Test 1: Parse simple key=value
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config("rpcuser=admin\nrpcpassword=secret\n");
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.get("rpcuser") == "admin");
        assert(cfg.get("rpcpassword") == "secret");
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 2: Parse with hash comments
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config(
            "# This is a comment\n"
            "key1=value1\n"
            "# Another comment\n"
            "key2=value2\n"
        );
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.get("key1") == "value1");
        assert(cfg.get("key2") == "value2");
        assert(!cfg.has("#"));
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 3: Parse with semicolon comments
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config(
            "; Semicolon comment\n"
            "key=val\n"
        );
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.get("key") == "val");
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 4: Parse with whitespace (trimmed)
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config(
            "  key1  =  value1  \n"
            "\tkey2\t=\tvalue2\t\n"
        );
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.get("key1") == "value1");
        assert(cfg.get("key2") == "value2");
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 5: Parse empty lines (skipped)
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config(
            "\n"
            "key1=val1\n"
            "\n"
            "\n"
            "key2=val2\n"
            "\n"
        );
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.get("key1") == "val1");
        assert(cfg.get("key2") == "val2");
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 6: Last value wins for duplicate keys (single map)
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config(
            "key=first\n"
            "key=second\n"
        );
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.get("key") == "second");
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 7: get_string with default for missing key
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config("existing=yes\n");
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.get("existing") == "yes");
        assert(cfg.get("missing") == "");
        assert(cfg.get("missing", "fallback") == "fallback");
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 8: get_int with default for missing and present keys
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config(
            "port=9333\n"
            "maxconnections=125\n"
            "notanumber=abc\n"
        );
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.get_int("port") == 9333);
        assert(cfg.get_int("maxconnections") == 125);
        assert(cfg.get_int("missing", 42) == 42);
        // Non-numeric value returns default
        assert(cfg.get_int("notanumber", 99) == 99);
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 9: get_bool (true/1/yes, false/0/no)
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config(
            "a=true\n"
            "b=1\n"
            "c=yes\n"
            "d=false\n"
            "e=0\n"
            "f=no\n"
            "g=TRUE\n"
            "h=YES\n"
            "i=False\n"
            "j=No\n"
        );
        flow::Config cfg;
        assert(cfg.load(path));

        assert(cfg.get_bool("a") == true);
        assert(cfg.get_bool("b") == true);
        assert(cfg.get_bool("c") == true);
        assert(cfg.get_bool("d") == false);
        assert(cfg.get_bool("e") == false);
        assert(cfg.get_bool("f") == false);
        assert(cfg.get_bool("g") == true);
        assert(cfg.get_bool("h") == true);
        assert(cfg.get_bool("i") == false);
        assert(cfg.get_bool("j") == false);

        // Missing key with default
        assert(cfg.get_bool("missing", true) == true);
        assert(cfg.get_bool("missing", false) == false);

        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 10: has() for existing and missing keys
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config("exist=val\n");
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.has("exist") == true);
        assert(cfg.has("noexist") == false);
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 11: set() and then get()
    // -----------------------------------------------------------------------
    {
        flow::Config cfg;
        cfg.set("dynamic_key", "dynamic_value");
        assert(cfg.has("dynamic_key"));
        assert(cfg.get("dynamic_key") == "dynamic_value");
    }

    // -----------------------------------------------------------------------
    // Test 12: set() overrides loaded value
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config("key=original\n");
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.get("key") == "original");

        cfg.set("key", "overridden");
        assert(cfg.get("key") == "overridden");
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 13: Invalid lines handled gracefully (no crash)
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config(
            "valid_key=valid_value\n"
            "noequalssign\n"
            "=no_key\n"
            "another_valid=ok\n"
        );
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.get("valid_key") == "valid_value");
        assert(cfg.get("another_valid") == "ok");
        // Line without '=' is silently skipped
        assert(!cfg.has("noequalssign"));
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 14: Loading non-existent file returns false
    // -----------------------------------------------------------------------
    {
        flow::Config cfg;
        assert(!cfg.load("/tmp/flowcoin_nonexistent_file_xyz.conf"));
    }

    // -----------------------------------------------------------------------
    // Test 15: Empty file loads successfully
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config("");
        flow::Config cfg;
        assert(cfg.load(path));
        assert(!cfg.has("anything"));
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 16: Value with equals sign in it
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config("rpcpassword=pass=word=123\n");
        flow::Config cfg;
        assert(cfg.load(path));
        // The first '=' splits key from value; remaining '=' are part of value
        assert(cfg.get("rpcpassword") == "pass=word=123");
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 17: get_int for negative values
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config("offset=-100\n");
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.get_int("offset") == -100);
        remove_temp(path);
    }

    // -----------------------------------------------------------------------
    // Test 18: Only whitespace lines are skipped
    // -----------------------------------------------------------------------
    {
        std::string path = write_temp_config(
            "   \n"
            "\t\t\n"
            "  \t  \n"
            "key=val\n"
        );
        flow::Config cfg;
        assert(cfg.load(path));
        assert(cfg.get("key") == "val");
        remove_temp(path);
    }
}
