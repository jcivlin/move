// use-stdlib

module 0x10::ascii_tests {
    use 0x1::ascii;
    use 0x1::vector;
    use 0x1::option;

    public fun test_ascii_chars() {
        let i = 0;
        let end = 128;
        let vec = vector::empty();

        while (i < end) {
            assert!(ascii::is_valid_char(i), 0);
            vector::push_back(&mut vec, i);
            i = i + 1;
        };

        let str = ascii::string(vec);
        assert!(vector::length(ascii::as_bytes(&str)) == 128, 0);
        assert!(!ascii::all_characters_printable(&str), 1);
        assert!(vector::length(&ascii::into_bytes(str)) == 128, 2);
    }

    public fun test_ascii_push_chars() {
        let i = 0;
        let end = 128;
        let str = ascii::string(vector::empty());

        while (i < end) {
            ascii::push_char(&mut str, ascii::char(i));
            i = i + 1;
        };

        assert!(vector::length(ascii::as_bytes(&str)) == 128, 0);
        assert!(ascii::length(&str) == 128, 0);
        assert!(!ascii::all_characters_printable(&str), 1);
    }

    public fun test_ascii_push_char_pop_char() {
        let i = 0;
        let end = 128;
        let str = ascii::string(vector::empty());

        while (i < end) {
            ascii::push_char(&mut str, ascii::char(i));
            i = i + 1;
        };

        while (i > 0) {
            let char = ascii::pop_char(&mut str);
            assert!(ascii::byte(char) == i - 1, 0);
            i = i - 1;
        };

        assert!(vector::length(ascii::as_bytes(&str)) == 0, 0);
        assert!(ascii::length(&str) == 0, 0);
        assert!(ascii::all_characters_printable(&str), 1);
    }

    public fun test_printable_chars() {
        let i = 0x20;
        let end = 0x7E;
        let vec = vector::empty();

        while (i <= end) {
            assert!(ascii::is_printable_char(i), 0);
            vector::push_back(&mut vec, i);
            i = i + 1;
        };

        let str = ascii::string(vec);
        assert!(ascii::all_characters_printable(&str), 0);
    }

    public fun printable_chars_dont_allow_tab() {
        let str = ascii::string(vector::singleton(0x09));
        assert!(!ascii::all_characters_printable(&str), 0);
    }

    public fun printable_chars_dont_allow_newline() {
        let str = ascii::string(vector::singleton(0x0A));
        assert!(!ascii::all_characters_printable(&str), 0);
    }

    public fun test_invalid_ascii_characters() {
        let i = 128u8;
        let end = 255u8;
        while (i < end) {
            let try_str = ascii::try_string(vector::singleton(i));
            assert!(option::is_none(&try_str), 0);
            i = i + 1;
        };
    }

    public fun test_nonvisible_chars() {
        let i = 0;
        let end = 0x09;
        while (i < end) {
            let str = ascii::string(vector::singleton(i));
            assert!(!ascii::all_characters_printable(&str), 0);
            i = i + 1;
        };

        let i = 0x0B;
        let end = 0x0F;
        while (i <= end) {
            let str = ascii::string(vector::singleton(i));
            assert!(!ascii::all_characters_printable(&str), 0);
            i = i + 1;
        };
    }
}

script {
    use 0x10::ascii_tests as AT;

    fun main() {
        AT::test_ascii_chars();
        AT::test_ascii_push_chars();
        AT::test_ascii_push_char_pop_char();
        AT::test_printable_chars();
        AT::printable_chars_dont_allow_tab();
        AT::printable_chars_dont_allow_newline();
        AT::test_invalid_ascii_characters();
        AT::test_nonvisible_chars();
    }
}
