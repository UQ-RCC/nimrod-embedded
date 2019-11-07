#include <fstream>
#include <regex>
#include <string_view>
#include <iomanip>
#include <optional>
#include "nimrun.hpp"

void process_shellfile(const fs::path& file, const fs::path& planpath, const fs::path& scriptpath, const fs::path& outdir, const fs::path& errdir, int argc, char **argv)
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
	](std::string_view v, size_t i) {
		std::match_results<std::string_view::const_iterator> m;

		/* See if we have an initial #! as we'll need to replace it if we do. */
		if(i == 0)
		{
			has_shebang = v.substr(0, std::min(v.size(), size_t(2))) == "#!";
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

		for_each_delim(indata.get(), indata.get() + size, '\n', [&os, &has_shebang, &shebang](std::string_view v, size_t i) {
			if(i == 0)
			{
				os << "#!" << shebang.value_or("/bin/sh") << '\n';

				if(has_shebang)
					return;
			}

			os << v << '\n';
		});

		fs::permissions(scriptpath, fs::perms::owner_all);
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
		for(int i = 1; i < argc; ++i)
			os << " " << std::quoted(argv[i]);
		os << std::endl;

		fs::path o = outdir / "stdout-$jobindex.txt";
		fs::path e = errdir / "stderr-$jobindex.txt";

		os << "\tcopy node:stdout.txt root:" << std::quoted(o.c_str()) << std::endl;
		os << "\tcopy node:stderr.txt root:" << std::quoted(e.c_str()) << std::endl;
		os << "endtask" << std::endl;

		fs::permissions(planpath, fs::perms::owner_read | fs::perms::owner_write);
	}
}
