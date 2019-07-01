#include <fstream>
#include <regex>
#include <string_view>
#include <iomanip>
#include <optional>
#include "nimrun.hpp"

template<
    typename V,
    typename CharT = char,
    typename InputIt = const CharT*,
    typename Traits = std::char_traits<CharT>,
    typename ViewT = std::basic_string_view<CharT, Traits>
>
void for_each_delim(InputIt begin, InputIt end, CharT delim, V&& proc)
{
	size_t i = 0;
	for(InputIt start = begin, next; start != end; start = next, ++i)
	{
		if((next = std::find(start, end, delim)) != end)
		{
			proc(ViewT(start, std::distance(start, next)), i);
			++next;
		}
	}
}

void process_shellfile(const fs::path& file, const fs::path& planpath, const fs::path& scriptpath, int argc, char **argv)
{
	/* The number of memory allocations these do is disgusting. */
	std::regex regex_hashnim("^#NIM\\s+.+$", std::regex_constants::ECMAScript);
	std::regex regex_hashnim_shebang("^#NIM\\s+shebang\\s*(.+)$", std::regex_constants::ECMAScript);

	/* \1 = parameter string, \2 = parameter name */
	std::regex regex_hashnim_parameter("^#NIM\\s+(parameter\\s*([a-zA-Z_][a-zA-Z0-9]*)\\s*.+)$", std::regex_constants::ECMAScript);

	size_t size;
	std::unique_ptr<char[]> indata = read_file(file.c_str(), size);
	if(!indata)
		throw std::runtime_error("file doesn't exist");

	bool has_shebang = false;
	std::optional<std::string> shebang;
	std::unordered_map<std::string, std::string> parameters;

	for_each_delim(indata.get(), indata.get() + size, '\n', [
		&regex_hashnim, &regex_hashnim_shebang, &regex_hashnim_parameter,
		&has_shebang, &shebang, &parameters
	](const std::string_view& v, size_t i) {
		std::match_results<std::string_view::const_iterator> m;

		/* See if we have an initial #! as we'll need to replace it if we do. */
		if(i == 0)
		{
			has_shebang = strncmp("#!", v.data(), std::min(v.size(), size_t(2))) == 0;
			return;
		}

		/* Ignore any non #NIM lines. */
		if(!std::regex_match(v.begin(), v.end(), m, regex_hashnim))
			return;

		if(std::regex_match(v.begin(), v.end(), m, regex_hashnim_shebang))
			shebang = m[1];

		if(std::regex_match(v.begin(), v.end(), m, regex_hashnim_parameter))
			parameters[m[2]] = m[1];
	});

	{
		/* Write the processed script. */
		std::ofstream os(scriptpath, std::ios::out | std::ios::binary);
		os.exceptions(std::ios::badbit | std::ios::failbit);

		for_each_delim(indata.get(), indata.get() + size, '\n', [&os, &has_shebang, &shebang](const std::string_view& v, size_t i) {
			if(i == 0)
			{
				os << "#!" << shebang.value_or("/bin/sh") << '\n';

				if(has_shebang)
					return;
			}

			os << v << '\n';
		});

		fs::permissions(scriptpath, fs::perms::owner_all, fs::perm_options::replace);
	}

	{
		/* Write the generated planfile. */
		std::ofstream os(planpath, std::ios::out | std::ios::binary);
		os.exceptions(std::ios::badbit | std::ios::failbit);

		for(auto& p : parameters)
			os << p.second << std::endl;
		os << std::endl;
		os << "task main" << std::endl;
		os << "\tonerror fail" << std::endl;
		os << "\tredirect stdout to stdout.txt" << std::endl;
		os << "\tredirect stderr to stderr.txt" << std::endl;

		os << "\texec " << scriptpath;
		for(size_t i = 1; i < argc; ++i)
			os << " " << std::quoted(argv[i]);
		os << std::endl;

		os << "\tcopy node:stdout.txt root:stdout-$jobindex.txt" << std::endl;
		os << "\tcopy node:stderr.txt root:stderr-$jobindex.txt" << std::endl;
		os << "endtask" << std::endl;

		fs::permissions(planpath, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
	}
}